"""Convergent SCIM provisioning with replay and deprovision precedence."""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import Lock
from typing import Any, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import Connection, CursorResult, Engine
from sqlalchemy.orm import Session, aliased, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    ProjectMembershipRecord,
    ResourceGrantRecord,
    SpaceMembership,
    TenantMembership,
)
from saas.control_plane.enterprise_identity_models import (
    EnterpriseScimDirectoryRecord,
    EnterpriseScimEventRecord,
    EnterpriseScimGroupRecord,
    EnterpriseScimUserRecord,
)
from saas.control_plane.enterprise_models import (
    EnterpriseGroupMembershipRecord,
    EnterpriseGroupRecord,
)
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import TENANT_ROLE_PERMISSIONS
from saas.control_plane.privacy_lifecycle import scim_user_locator_hash
from saas.control_plane.privacy_models import PrivacyIdentityTombstoneRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scim_syntax import ScimFilterExpression, expected_core_schema


@dataclass(frozen=True, slots=True)
class IssuedScimDirectory:
    id: UUID
    tenant_id: UUID
    display_name: str
    token_prefix: str
    successor_token_prefix: str | None
    rotation_activates_at: datetime | None
    rotation_grace_expires_at: datetime | None
    status: str
    version: int
    bearer_token: str | None
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ScimUserView:
    id: UUID
    directory_id: UUID
    tenant_id: UUID
    user_id: UUID | None
    external_id: str
    user_name: str
    display_name: str | None
    active: bool
    version: int
    source_version: int
    membership_status: str | None
    requires_owner_recovery: bool
    revoked_session_count: int
    disposition: str
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ScimGroupView:
    id: UUID
    directory_id: UUID
    tenant_id: UUID
    enterprise_group_id: UUID
    external_id: str
    display_name: str
    active: bool
    version: int
    source_version: int
    active_member_count: int
    member_scim_user_ids: tuple[UUID, ...]
    blocked_external_ids: tuple[str, ...]
    disposition: str
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ScimUserPage:
    resources: tuple[ScimUserView, ...]
    total_results: int
    start_index: int
    items_per_page: int


@dataclass(frozen=True, slots=True)
class ScimGroupPage:
    resources: tuple[ScimGroupView, ...]
    total_results: int
    start_index: int
    items_per_page: int


@dataclass(slots=True)
class ScimBulkExecution:
    """One serialized Bulk request with an optional immutable replay result."""

    replay_result: dict[str, object] | None = None
    response: dict[str, object] | None = None

    def complete(self, response: dict[str, object]) -> None:
        if self.replay_result is not None or self.response is not None:
            raise LifecycleError(
                "scim_bulk_state_invalid", "SCIM Bulk request is already complete"
            )
        self.response = response


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash(payload: Mapping[str, object]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _clean(value: str, *, maximum: int, code: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise LifecycleError(code, "value is invalid")
    return cleaned


def _normalize_user_name(value: str) -> str:
    return _clean(value, maximum=320, code="scim_user_name_invalid").casefold()


def _integer(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise LifecycleError("scim_receipt_invalid", f"{key} is invalid")
    return value


def _optional_datetime(payload: Mapping[str, object], key: str) -> datetime | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise LifecycleError("scim_receipt_invalid", f"{key} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise LifecycleError("scim_receipt_invalid", f"{key} is invalid") from error
    if parsed.tzinfo is None:
        raise LifecycleError("scim_receipt_invalid", f"{key} is invalid")
    return parsed.astimezone(timezone.utc)


def _rotation_time(value: datetime, *, code: str) -> datetime:
    if value.tzinfo is None:
        raise LifecycleError(code, "rotation time must include a timezone")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise LifecycleError(code, "rotation time is invalid") from error


def _stored_rotation_time(value: datetime, *, code: str) -> datetime:
    stored = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    try:
        return stored.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise LifecycleError(code, "stored rotation time is invalid") from error


def _require_fresh_auth(reauthenticated_at: datetime, now: datetime) -> None:
    authenticated = (
        reauthenticated_at
        if reauthenticated_at.tzinfo is not None
        else reauthenticated_at.replace(tzinfo=timezone.utc)
    )
    current = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    if authenticated > current or current - authenticated > timedelta(minutes=5):
        raise LifecycleError("fresh_auth_required", "recent authentication is required")


class EnterpriseScimService:
    """Own one-way SCIM convergence without treating email as identity proof."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        self._bulk_locks = tuple(Lock() for _ in range(64))

    def issue_directory(
        self,
        request: RequestContext,
        *,
        display_name: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedScimDirectory:
        issued_at = now or _utcnow()
        _require_fresh_auth(reauthenticated_at, issued_at)
        name = _clean(display_name, maximum=128, code="scim_directory_name_invalid")
        key = _clean(idempotency_key, maximum=128, code="invalid_idempotency_key")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "display_name": name,
        }
        request_hash = _hash(payload)
        receipt_key = f"scim-directory:{request.tenant_id}:{_digest(key)[:48]}"
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            self._require_manage(db, request)
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key has a different request"
                    )
                return self._issued_directory(receipt.payload, bearer_token=None, replayed=True)

            raw_token = f"omniscim_{secrets.token_urlsafe(8)}_{secrets.token_urlsafe(32)}"
            token_hash = _digest(raw_token)
            directory = EnterpriseScimDirectoryRecord(
                id=uuid4(),
                tenant_id=request.tenant_id,
                display_name=name,
                token_hash=token_hash,
                token_prefix=raw_token[:24],
                status="active",
                version=1,
                configured_by=request.actor_id,
            )
            db.add(directory)
            db.flush()
            result: dict[str, object] = {
                **payload,
                "directory_id": str(directory.id),
                "token_prefix": directory.token_prefix,
                "status": directory.status,
                "version": directory.version,
            }
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=request.tenant_id,
                    aggregate_type="enterprise_scim_directory",
                    aggregate_key=str(directory.id),
                    event_type="enterprise.scim_directory.issued",
                    payload=result,
                    idempotency_key=receipt_key,
                    request_hash=request_hash,
                )
            )
            return self._issued_directory(result, bearer_token=raw_token, replayed=False)

    def rotate_directory_credential(
        self,
        request: RequestContext,
        *,
        directory_id: UUID,
        expected_version: int,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedScimDirectory:
        """Replace one active Directory credential and reveal the new token once."""

        rotated_at = now or _utcnow()
        _require_fresh_auth(reauthenticated_at, rotated_at)
        return self._mutate_directory_credential(
            request,
            directory_id=directory_id,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            action="rotate",
            changed_at=rotated_at,
        )

    def disable_directory(
        self,
        request: RequestContext,
        *,
        directory_id: UUID,
        expected_version: int,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedScimDirectory:
        """Disable one Directory and destroy its credential digest atomically."""

        disabled_at = now or _utcnow()
        _require_fresh_auth(reauthenticated_at, disabled_at)
        return self._mutate_directory_credential(
            request,
            directory_id=directory_id,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            action="disable",
            changed_at=disabled_at,
        )

    def schedule_directory_credential_rotation(
        self,
        request: RequestContext,
        *,
        directory_id: UUID,
        expected_version: int,
        activates_at: datetime,
        grace_period_seconds: int,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedScimDirectory:
        """Issue a successor token with bounded activation and dual-token grace windows."""

        scheduled_at = now or _utcnow()
        _require_fresh_auth(reauthenticated_at, scheduled_at)
        activation = _rotation_time(
            activates_at,
            code="scim_directory_rotation_time_invalid",
        )
        if (
            not isinstance(grace_period_seconds, int)
            or isinstance(grace_period_seconds, bool)
            or not 60 <= grace_period_seconds <= 86_400
        ):
            raise LifecycleError(
                "scim_directory_rotation_grace_invalid",
                "rotation grace period must be between 60 and 86400 seconds",
            )
        try:
            grace_expires_at = activation + timedelta(seconds=grace_period_seconds)
        except OverflowError as error:
            raise LifecycleError(
                "scim_directory_rotation_time_invalid",
                "rotation time is invalid",
            ) from error
        return self._mutate_directory_credential(
            request,
            directory_id=directory_id,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            action="schedule",
            changed_at=scheduled_at,
            rotation_activates_at=activation,
            rotation_grace_expires_at=grace_expires_at,
        )

    def _mutate_directory_credential(
        self,
        request: RequestContext,
        *,
        directory_id: UUID,
        expected_version: int,
        idempotency_key: str,
        action: str,
        changed_at: datetime,
        rotation_activates_at: datetime | None = None,
        rotation_grace_expires_at: datetime | None = None,
    ) -> IssuedScimDirectory:
        if expected_version < 1:
            raise LifecycleError("scim_directory_version_invalid", "version is invalid")
        key = _clean(idempotency_key, maximum=128, code="invalid_idempotency_key")
        request_payload: dict[str, object] = {
            "action": action,
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "directory_id": str(directory_id),
            "expected_version": expected_version,
        }
        if action == "schedule":
            if rotation_activates_at is None or rotation_grace_expires_at is None:
                raise ValueError("scheduled rotation requires activation and grace deadlines")
            request_payload.update(
                {
                    "rotation_activates_at": rotation_activates_at.isoformat(),
                    "rotation_grace_expires_at": rotation_grace_expires_at.isoformat(),
                }
            )
        request_hash = _hash(request_payload)
        receipt_key = (
            f"scim-directory-{action}:{request.tenant_id}:{_digest(f'{directory_id}:{key}')[:48]}"
        )
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            self._require_manage(db, request)
            directory = db.execute(
                sa.select(EnterpriseScimDirectoryRecord)
                .where(
                    EnterpriseScimDirectoryRecord.tenant_id == request.tenant_id,
                    EnterpriseScimDirectoryRecord.id == directory_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if directory is None:
                raise LifecycleError("scim_directory_not_found", "SCIM Directory was not found")

            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key has a different request"
                    )
                return self._issued_directory(receipt.payload, bearer_token=None, replayed=True)
            if action == "schedule" and (
                rotation_activates_at is None
                or rotation_grace_expires_at is None
                or rotation_activates_at < changed_at - timedelta(minutes=1)
                or rotation_activates_at > changed_at + timedelta(days=30)
                or rotation_grace_expires_at <= changed_at
            ):
                raise LifecycleError(
                    "scim_directory_rotation_time_invalid",
                    "rotation activation must be current or within 30 days",
                )
            if directory.version != expected_version:
                raise LifecycleError(
                    "scim_directory_version_conflict", "SCIM Directory version changed"
                )
            if directory.status != "active":
                raise LifecycleError(
                    "scim_directory_not_active", "active SCIM Directory is required"
                )

            if directory.successor_token_hash is not None and action != "disable":
                grace_expires_at = directory.rotation_grace_expires_at
                if grace_expires_at is None:
                    raise LifecycleError(
                        "scim_directory_rotation_state_invalid",
                        "SCIM Directory rotation state is invalid",
                    )
                grace_expires = _stored_rotation_time(
                    grace_expires_at,
                    code="scim_directory_rotation_state_invalid",
                )
                if changed_at < grace_expires:
                    raise LifecycleError(
                        "scim_directory_rotation_in_progress",
                        "SCIM Directory credential rotation is still in progress",
                    )
                directory.token_hash = directory.successor_token_hash
                directory.token_prefix = cast(str, directory.successor_token_prefix)
                self._clear_directory_successor(directory)

            raw_token: str | None = None
            if action == "rotate":
                raw_token = f"omniscim_{secrets.token_urlsafe(8)}_{secrets.token_urlsafe(32)}"
                directory.token_hash = _digest(raw_token)
                directory.token_prefix = raw_token[:24]
                directory.rotated_at = changed_at
                event_type = "enterprise.scim_directory.credential_rotated"
            elif action == "schedule":
                raw_token = f"omniscim_{secrets.token_urlsafe(8)}_{secrets.token_urlsafe(32)}"
                directory.successor_token_hash = _digest(raw_token)
                directory.successor_token_prefix = raw_token[:24]
                directory.rotation_activates_at = rotation_activates_at
                directory.rotation_grace_expires_at = rotation_grace_expires_at
                directory.rotated_at = changed_at
                event_type = "enterprise.scim_directory.credential_rotation_scheduled"
            elif action == "disable":
                directory.token_hash = _digest(
                    f"disabled:{directory.id}:{secrets.token_urlsafe(32)}"
                )
                directory.token_prefix = "disabled"
                directory.status = "disabled"
                directory.disabled_at = changed_at
                self._clear_directory_successor(directory)
                event_type = "enterprise.scim_directory.disabled"
            else:  # pragma: no cover - private call contract
                raise ValueError("unsupported SCIM Directory action")
            directory.configured_by = request.actor_id
            directory.version += 1
            db.flush()
            result: dict[str, object] = {
                **request_payload,
                "display_name": directory.display_name,
                "token_prefix": directory.token_prefix,
                "successor_token_prefix": directory.successor_token_prefix,
                "rotation_activates_at": (
                    directory.rotation_activates_at.isoformat()
                    if directory.rotation_activates_at is not None
                    else None
                ),
                "rotation_grace_expires_at": (
                    directory.rotation_grace_expires_at.isoformat()
                    if directory.rotation_grace_expires_at is not None
                    else None
                ),
                "status": directory.status,
                "version": directory.version,
            }
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=request.tenant_id,
                    aggregate_type="enterprise_scim_directory",
                    aggregate_key=str(directory.id),
                    event_type=event_type,
                    payload=result,
                    idempotency_key=receipt_key,
                    request_hash=request_hash,
                )
            )
            return self._issued_directory(result, bearer_token=raw_token, replayed=False)

    @staticmethod
    def _clear_directory_successor(directory: EnterpriseScimDirectoryRecord) -> None:
        directory.successor_token_hash = None
        directory.successor_token_prefix = None
        directory.rotation_activates_at = None
        directory.rotation_grace_expires_at = None

    @contextmanager
    def bulk_request(
        self,
        bearer_token: str,
        *,
        event_id: str,
        request_payload: Mapping[str, object],
        operation_count: int,
    ) -> Iterator[ScimBulkExecution]:
        """Serialize one Bulk key and persist immutable request/result receipts."""

        event_key = _clean(event_id, maximum=256, code="scim_event_id_invalid")
        if not 1 <= operation_count <= 32:
            raise LifecycleError("tooMany", "SCIM Bulk operation count is invalid")
        request_hash = _hash(request_payload)
        event_digest = _digest(event_key)
        request_event_id = f"bulk-request:{event_digest}"
        result_event_id = f"bulk-result:{event_digest}"
        with self._session_factory() as probe:
            bind = probe.get_bind()
            dialect = bind.dialect.name
        if dialect == "postgresql":
            with self._session_factory.begin() as db:
                directory_id = self._authenticate(db, bearer_token).id
            advisory_key = f"scim-bulk:{directory_id}:{event_digest}"
            engine = bind.engine if isinstance(bind, Connection) else cast(Engine, bind)
            lock_connection = engine.connect()
            try:
                lock_connection.execute(
                    sa.text("SELECT pg_advisory_lock(hashtextextended(:key, 0))"),
                    {"key": advisory_key},
                )
                with self._session_factory.begin() as db:
                    directory = self._authenticate(db, bearer_token)
                    if directory.id != directory_id:
                        raise LifecycleError(
                            "scim_authentication_failed", "SCIM Directory changed during Bulk"
                        )
                    execution = self._prepare_bulk_execution(
                        db,
                        directory,
                        request_event_id=request_event_id,
                        result_event_id=result_event_id,
                        request_hash=request_hash,
                        operation_count=operation_count,
                    )
                yield execution
                if execution.replay_result is None:
                    with self._session_factory.begin() as db:
                        directory = self._authenticate(db, bearer_token)
                        if directory.id != directory_id:
                            raise LifecycleError(
                                "scim_authentication_failed",
                                "SCIM Directory changed during Bulk",
                            )
                        self._finish_bulk_execution(
                            db,
                            directory,
                            execution=execution,
                            result_event_id=result_event_id,
                            request_hash=request_hash,
                            operation_count=operation_count,
                        )
            finally:
                lock_connection.execute(
                    sa.text("SELECT pg_advisory_unlock(hashtextextended(:key, 0))"),
                    {"key": advisory_key},
                )
                lock_connection.close()
            return

        lock = self._bulk_locks[int(event_digest[:8], 16) % len(self._bulk_locks)]
        with lock:
            with self._session_factory.begin() as db:
                directory = self._authenticate(db, bearer_token)
                execution = self._prepare_bulk_execution(
                    db,
                    directory,
                    request_event_id=request_event_id,
                    result_event_id=result_event_id,
                    request_hash=request_hash,
                    operation_count=operation_count,
                )
                directory_id = directory.id
            yield execution
            if execution.replay_result is None:
                with self._session_factory.begin() as db:
                    directory = self._authenticate(db, bearer_token)
                    if directory.id != directory_id:
                        raise LifecycleError(
                            "scim_authentication_failed", "SCIM Directory changed during Bulk"
                        )
                    self._finish_bulk_execution(
                        db,
                        directory,
                        execution=execution,
                        result_event_id=result_event_id,
                        request_hash=request_hash,
                        operation_count=operation_count,
                    )

    def _prepare_bulk_execution(
        self,
        db: Session,
        directory: EnterpriseScimDirectoryRecord,
        *,
        request_event_id: str,
        result_event_id: str,
        request_hash: str,
        operation_count: int,
    ) -> ScimBulkExecution:
        completed = self._event_replay(db, directory.id, result_event_id, request_hash)
        if completed is not None:
            return ScimBulkExecution(replay_result=dict(completed.result))
        claimed = self._event_replay(db, directory.id, request_event_id, request_hash)
        if claimed is None:
            self._record_event(
                db,
                directory,
                request_event_id,
                request_hash,
                "Bulk",
                directory.id,
                1,
                "applied",
                {"phase": "requested", "operationCount": operation_count},
                event_type="enterprise.scim_bulk.requested",
            )
        return ScimBulkExecution()

    def _finish_bulk_execution(
        self,
        db: Session,
        directory: EnterpriseScimDirectoryRecord,
        *,
        execution: ScimBulkExecution,
        result_event_id: str,
        request_hash: str,
        operation_count: int,
    ) -> None:
        if execution.replay_result is not None:
            return
        if execution.response is None:
            raise LifecycleError("scim_bulk_incomplete", "SCIM Bulk response was not completed")
        operations = execution.response.get("Operations")
        if not isinstance(operations, list) or len(operations) > operation_count:
            raise LifecycleError("scim_bulk_state_invalid", "SCIM Bulk response is invalid")
        existing = self._event_replay(db, directory.id, result_event_id, request_hash)
        if existing is None:
            self._record_event(
                db,
                directory,
                result_event_id,
                request_hash,
                "Bulk",
                directory.id,
                1,
                "applied",
                execution.response,
                event_type="enterprise.scim_bulk.completed",
            )

    def upsert_user(
        self,
        bearer_token: str,
        *,
        event_id: str,
        external_id: str,
        user_name: str,
        display_name: str | None,
        active: bool,
        source_version: int | None,
        scim_user_id: UUID | None = None,
        expected_version: int | None = None,
        operation: str = "upsert",
    ) -> ScimUserView:
        event_key = _clean(event_id, maximum=256, code="scim_event_id_invalid")
        external = _clean(external_id, maximum=256, code="scim_external_id_invalid")
        normalized = _normalize_user_name(user_name)
        shown_name = (
            _clean(display_name, maximum=256, code="scim_display_name_invalid")
            if display_name is not None
            else None
        )
        guarded = scim_user_id is not None or expected_version is not None
        if guarded:
            if scim_user_id is None or expected_version is None or expected_version < 1:
                raise LifecycleError("scim_etag_mismatch", "current User ETag is required")
            if source_version is not None or operation not in {"replace", "patch", "delete"}:
                raise LifecycleError("scim_request_invalid", "guarded User mutation is invalid")
        elif source_version is None or source_version < 1 or operation != "upsert":
            raise LifecycleError("scim_source_version_invalid", "source version is invalid")
        desired: dict[str, object] = {
            "resource_type": "User",
            "external_id": external,
            "user_name": normalized,
            "display_name": shown_name,
            "active": active,
        }
        request_payload = (
            {
                **desired,
                "operation": operation,
                "resource_id": str(scim_user_id),
                "expected_version": expected_version,
            }
            if guarded
            else {**desired, "source_version": source_version}
        )
        request_hash = _hash(request_payload)
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            locator = scim_user_locator_hash(directory.id, external)
            apply_rls_context(
                db,
                RlsContext(
                    tenant_id=directory.tenant_id,
                    scim_token_hash=_digest(bearer_token),
                    privacy_locator_hash=locator,
                ),
            )
            if (
                db.execute(
                    sa.select(PrivacyIdentityTombstoneRecord.id).where(
                        PrivacyIdentityTombstoneRecord.locator_hash == locator
                    )
                ).scalar_one_or_none()
                is not None
            ):
                raise LifecycleError(
                    "scim_subject_deleted", "deleted SCIM subjects cannot be reprovisioned"
                )
            replay = self._event_replay(db, directory.id, event_key, request_hash)
            if replay is not None:
                return self._user_result(replay.result, replayed=True)

            user = db.execute(
                sa.select(EnterpriseScimUserRecord)
                .where(
                    EnterpriseScimUserRecord.directory_id == directory.id,
                    (
                        EnterpriseScimUserRecord.id == scim_user_id
                        if guarded
                        else EnterpriseScimUserRecord.external_id == external
                    ),
                )
                .with_for_update()
            ).scalar_one_or_none()
            if guarded:
                if user is None:
                    raise LifecycleError("scim_resource_not_found", "SCIM User was not found")
                if user.external_id != external:
                    raise LifecycleError(
                        "scim_external_id_immutable", "SCIM User externalId is immutable"
                    )
                if user.version != expected_version:
                    raise LifecycleError("scim_etag_mismatch", "SCIM User ETag changed")
                if (
                    operation == "patch"
                    and user.user_name_normalized == normalized
                    and user.display_name == shown_name
                    and user.active is active
                ):
                    result = self._user_payload(
                        db,
                        user,
                        disposition="applied",
                        requires_owner_recovery=False,
                        revoked_session_count=0,
                    )
                    self._record_event(
                        db,
                        directory,
                        event_key,
                        request_hash,
                        "User",
                        user.id,
                        user.source_version,
                        "applied",
                        result,
                        event_type="enterprise.scim_user.noop",
                    )
                    return self._user_result(result)
                source_version = user.source_version + 1
            assert source_version is not None
            state_hash = _hash(
                {
                    key: value
                    for key, value in {**desired, "source_version": source_version}.items()
                    if key != "resource_type"
                }
            )
            now = _utcnow()
            if user is not None and source_version < user.source_version:
                result = self._user_payload(
                    db,
                    user,
                    disposition="stale",
                    requires_owner_recovery=False,
                    revoked_session_count=0,
                )
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "User",
                    user.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._user_result(result)
            if user is not None and source_version == user.source_version:
                if state_hash != user.source_state_hash:
                    raise LifecycleError(
                        "scim_version_conflict",
                        "source version already represents a different User state",
                    )
                result = self._user_payload(
                    db,
                    user,
                    disposition="stale",
                    requires_owner_recovery=False,
                    revoked_session_count=0,
                )
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "User",
                    user.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._user_result(result)

            if user is None:
                global_user = (
                    self._create_global_user(db, normalized, shown_name) if active else None
                )
                if global_user is not None:
                    db.add(
                        TenantMembership(
                            tenant_id=directory.tenant_id,
                            user_id=global_user.id,
                            role="member",
                            status="active",
                            version=1,
                            joined_at=now,
                        )
                    )
                user = EnterpriseScimUserRecord(
                    id=uuid4(),
                    tenant_id=directory.tenant_id,
                    directory_id=directory.id,
                    external_id=external,
                    user_id=global_user.id if global_user else None,
                    user_name_normalized=normalized,
                    display_name=shown_name,
                    active=active,
                    version=1,
                    source_version=source_version,
                    source_state_hash=state_hash,
                    deprovisioned_at=None if active else now,
                )
                db.add(user)
                db.flush()
                result = self._user_payload(
                    db,
                    user,
                    disposition="applied",
                    requires_owner_recovery=False,
                    revoked_session_count=0,
                )
            else:
                revoked_sessions = 0
                owner_recovery = False
                user.user_name_normalized = normalized
                user.display_name = shown_name
                user.source_version = source_version
                user.source_state_hash = state_hash
                user.version += 1
                if active:
                    if user.user_id is None:
                        user.user_id = self._create_global_user(db, normalized, shown_name).id
                    membership = db.get(TenantMembership, (directory.tenant_id, user.user_id))
                    if membership is None:
                        db.add(
                            TenantMembership(
                                tenant_id=directory.tenant_id,
                                user_id=user.user_id,
                                role="member",
                                status="active",
                                version=1,
                                joined_at=now,
                            )
                        )
                    else:
                        membership.status = "active"
                        membership.version += 1
                        membership.joined_at = membership.joined_at or now
                    user.active = True
                    user.deprovisioned_at = None
                else:
                    user.active = False
                    user.deprovisioned_at = now
                    if user.user_id is not None:
                        owner_recovery, revoked_sessions = self._deprovision_user(
                            db, directory.tenant_id, user.user_id, now
                        )
                db.flush()
                result = self._user_payload(
                    db,
                    user,
                    disposition="blocked" if owner_recovery else "applied",
                    requires_owner_recovery=owner_recovery,
                    revoked_session_count=revoked_sessions,
                )
            disposition = str(result["disposition"])
            self._record_event(
                db,
                directory,
                event_key,
                request_hash,
                "User",
                user.id,
                source_version,
                disposition,
                result,
            )
            return self._user_result(result)

    def get_user(self, bearer_token: str, *, scim_user_id: UUID) -> ScimUserView:
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            user = db.execute(
                sa.select(EnterpriseScimUserRecord).where(
                    EnterpriseScimUserRecord.directory_id == directory.id,
                    EnterpriseScimUserRecord.id == scim_user_id,
                )
            ).scalar_one_or_none()
            if user is None:
                raise LifecycleError("scim_resource_not_found", "SCIM User was not found")
            return self._user_view(db, directory=directory, user=user)

    def list_users(
        self,
        bearer_token: str,
        *,
        start_index: int = 1,
        count: int = 100,
        filter_attribute: str | None = None,
        filter_value: str | None = None,
        filter_expression: ScimFilterExpression | None = None,
        sort_by: str | None = None,
        sort_order: str = "ascending",
    ) -> ScimUserPage:
        """List one Directory's Users with bounded filters and deterministic sorting."""

        resolved_filter = self._validate_list_request(
            start_index=start_index,
            count=count,
            filter_attribute=filter_attribute,
            filter_value=filter_value,
            filter_expression=filter_expression,
            resource_type="User",
            sort_by=sort_by,
            sort_order=sort_order,
        )
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            predicates: list[sa.ColumnElement[bool]] = [
                EnterpriseScimUserRecord.directory_id == directory.id
            ]
            if resolved_filter is not None:
                predicates.append(self._filter_predicate(resolved_filter, resource_type="User"))
            total = int(
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(EnterpriseScimUserRecord)
                    .where(*predicates)
                )
                or 0
            )
            users = tuple(
                db.scalars(
                    sa.select(EnterpriseScimUserRecord)
                    .where(*predicates)
                    .order_by(
                        *self._sort_expressions(
                            resource_type="User",
                            sort_by=sort_by,
                            sort_order=sort_order,
                        )
                    )
                    .offset(start_index - 1)
                    .limit(count)
                )
            )
            resources = tuple(
                self._user_view(db, directory=directory, user=user) for user in users
            )
            return ScimUserPage(
                resources=resources,
                total_results=total,
                start_index=start_index,
                items_per_page=len(resources),
            )

    def sync_group(
        self,
        bearer_token: str,
        *,
        event_id: str,
        external_id: str,
        display_name: str,
        member_external_ids: list[str],
        active: bool,
        source_version: int | None,
        scim_group_id: UUID | None = None,
        expected_version: int | None = None,
        operation: str = "upsert",
    ) -> ScimGroupView:
        event_key = _clean(event_id, maximum=256, code="scim_event_id_invalid")
        external = _clean(external_id, maximum=256, code="scim_external_id_invalid")
        name = _clean(display_name, maximum=128, code="scim_group_name_invalid")
        guarded = scim_group_id is not None or expected_version is not None
        if guarded:
            if scim_group_id is None or expected_version is None or expected_version < 1:
                raise LifecycleError("scim_etag_mismatch", "current Group ETag is required")
            if source_version is not None or operation not in {"replace", "patch", "delete"}:
                raise LifecycleError("scim_request_invalid", "guarded Group mutation is invalid")
        elif source_version is None or source_version < 1 or operation != "upsert":
            raise LifecycleError("scim_source_version_invalid", "source version is invalid")
        if len(member_external_ids) > 1000:
            raise LifecycleError("scim_group_members_invalid", "too many group members")
        members = tuple(
            sorted(
                {
                    _clean(item, maximum=256, code="scim_external_id_invalid")
                    for item in member_external_ids
                }
            )
        )
        desired: dict[str, object] = {
            "resource_type": "Group",
            "external_id": external,
            "display_name": name,
            "members": list(members),
            "active": active,
        }
        request_payload = (
            {
                **desired,
                "operation": operation,
                "resource_id": str(scim_group_id),
                "expected_version": expected_version,
            }
            if guarded
            else {**desired, "source_version": source_version}
        )
        request_hash = _hash(request_payload)
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            replay = self._event_replay(db, directory.id, event_key, request_hash)
            if replay is not None:
                return self._group_result(replay.result, replayed=True)
            group = db.execute(
                sa.select(EnterpriseScimGroupRecord)
                .where(
                    EnterpriseScimGroupRecord.directory_id == directory.id,
                    (
                        EnterpriseScimGroupRecord.id == scim_group_id
                        if guarded
                        else EnterpriseScimGroupRecord.external_id == external
                    ),
                )
                .with_for_update()
            ).scalar_one_or_none()
            if guarded:
                if group is None:
                    raise LifecycleError("scim_resource_not_found", "SCIM Group was not found")
                if group.external_id != external:
                    raise LifecycleError(
                        "scim_external_id_immutable", "SCIM Group externalId is immutable"
                    )
                if group.version != expected_version:
                    raise LifecycleError("scim_etag_mismatch", "SCIM Group ETag changed")
                if (
                    operation == "patch"
                    and group.display_name == name
                    and group.active is active
                    and self._current_group_member_external_ids(
                        db,
                        directory=directory,
                        group=group,
                    )
                    == members
                ):
                    result = self._group_payload(db, group, (), "applied")
                    self._record_event(
                        db,
                        directory,
                        event_key,
                        request_hash,
                        "Group",
                        group.id,
                        group.source_version,
                        "applied",
                        result,
                        event_type="enterprise.scim_group.noop",
                    )
                    return self._group_result(result)
                source_version = group.source_version + 1
            assert source_version is not None
            state_hash = _hash(
                {
                    key: value
                    for key, value in {**desired, "source_version": source_version}.items()
                    if key != "resource_type"
                }
            )
            if group is not None and source_version < group.source_version:
                result = self._group_payload(db, group, (), "stale")
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "Group",
                    group.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._group_result(result)
            if group is not None and source_version == group.source_version:
                if state_hash != group.source_state_hash:
                    raise LifecycleError(
                        "scim_version_conflict",
                        "source version already represents a different Group state",
                    )
                result = self._group_payload(db, group, (), "stale")
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "Group",
                    group.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._group_result(result)

            if group is None:
                enterprise_group = EnterpriseGroupRecord(
                    id=uuid4(),
                    tenant_id=directory.tenant_id,
                    name=name,
                    description="Managed by SCIM",
                    status="active" if active else "archived",
                    version=1,
                    created_by=directory.configured_by,
                    archived_at=None if active else _utcnow(),
                    archived_by=None if active else directory.configured_by,
                    archive_reason=None if active else "SCIM Group disabled",
                )
                db.add(enterprise_group)
                db.flush()
                group = EnterpriseScimGroupRecord(
                    id=uuid4(),
                    tenant_id=directory.tenant_id,
                    directory_id=directory.id,
                    external_id=external,
                    enterprise_group_id=enterprise_group.id,
                    display_name=name,
                    active=active,
                    version=1,
                    source_version=source_version,
                    source_state_hash=state_hash,
                )
                db.add(group)
                db.flush()
            else:
                enterprise_group = db.get(EnterpriseGroupRecord, group.enterprise_group_id)
                if enterprise_group is None:
                    raise LifecycleError("scim_group_not_found", "SCIM Group mapping is invalid")
                group.display_name = name
                group.active = active
                group.version += 1
                group.source_version = source_version
                group.source_state_hash = state_hash
                enterprise_group.name = name
                enterprise_group.version += 1
                if active:
                    enterprise_group.status = "active"
                    enterprise_group.archived_at = None
                    enterprise_group.archived_by = None
                    enterprise_group.archive_reason = None
                else:
                    enterprise_group.status = "archived"
                    enterprise_group.archived_at = _utcnow()
                    enterprise_group.archived_by = directory.configured_by
                    enterprise_group.archive_reason = "SCIM Group disabled"

            blocked = self._converge_group_members(
                db,
                directory=directory,
                group=group,
                desired_external_ids=members if active else (),
            )
            db.flush()
            result = self._group_payload(db, group, blocked, "blocked" if blocked else "applied")
            disposition = str(result["disposition"])
            self._record_event(
                db,
                directory,
                event_key,
                request_hash,
                "Group",
                group.id,
                source_version,
                disposition,
                result,
            )
            return self._group_result(result)

    def get_group(self, bearer_token: str, *, scim_group_id: UUID) -> ScimGroupView:
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            group = db.execute(
                sa.select(EnterpriseScimGroupRecord).where(
                    EnterpriseScimGroupRecord.directory_id == directory.id,
                    EnterpriseScimGroupRecord.id == scim_group_id,
                )
            ).scalar_one_or_none()
            if group is None:
                raise LifecycleError("scim_resource_not_found", "SCIM Group was not found")
            return self._group_result(self._group_payload(db, group, (), "applied"))

    def list_groups(
        self,
        bearer_token: str,
        *,
        start_index: int = 1,
        count: int = 100,
        filter_attribute: str | None = None,
        filter_value: str | None = None,
        filter_expression: ScimFilterExpression | None = None,
        sort_by: str | None = None,
        sort_order: str = "ascending",
    ) -> ScimGroupPage:
        """List one Directory's Groups with bounded filters and deterministic sorting."""

        resolved_filter = self._validate_list_request(
            start_index=start_index,
            count=count,
            filter_attribute=filter_attribute,
            filter_value=filter_value,
            filter_expression=filter_expression,
            resource_type="Group",
            sort_by=sort_by,
            sort_order=sort_order,
        )
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            predicates: list[sa.ColumnElement[bool]] = [
                EnterpriseScimGroupRecord.directory_id == directory.id
            ]
            if resolved_filter is not None:
                predicates.append(self._filter_predicate(resolved_filter, resource_type="Group"))
            total = int(
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(EnterpriseScimGroupRecord)
                    .where(*predicates)
                )
                or 0
            )
            groups = tuple(
                db.scalars(
                    sa.select(EnterpriseScimGroupRecord)
                    .where(*predicates)
                    .order_by(
                        *self._sort_expressions(
                            resource_type="Group",
                            sort_by=sort_by,
                            sort_order=sort_order,
                        )
                    )
                    .offset(start_index - 1)
                    .limit(count)
                )
            )
            resources = tuple(
                self._group_result(self._group_payload(db, group, (), "applied"))
                for group in groups
            )
            return ScimGroupPage(
                resources=resources,
                total_results=total,
                start_index=start_index,
                items_per_page=len(resources),
            )

    def _authenticate(self, db: Session, bearer_token: str) -> EnterpriseScimDirectoryRecord:
        token = _clean(bearer_token, maximum=256, code="scim_authentication_failed")
        token_hash = _digest(token)
        apply_rls_context(db, RlsContext(scim_token_hash=token_hash))
        directory = db.execute(
            sa.select(EnterpriseScimDirectoryRecord).where(
                sa.or_(
                    EnterpriseScimDirectoryRecord.token_hash == token_hash,
                    EnterpriseScimDirectoryRecord.successor_token_hash == token_hash,
                ),
                EnterpriseScimDirectoryRecord.status == "active",
            )
        ).scalar_one_or_none()
        if directory is None:
            raise LifecycleError("scim_authentication_failed", "SCIM credential is invalid")
        now = _utcnow()
        if directory.successor_token_hash == token_hash:
            activates_at = directory.rotation_activates_at
            if activates_at is None or now < _stored_rotation_time(
                activates_at,
                code="scim_directory_rotation_state_invalid",
            ):
                raise LifecycleError("scim_authentication_failed", "SCIM credential is invalid")
        elif directory.successor_token_hash is not None:
            grace_expires_at = directory.rotation_grace_expires_at
            if grace_expires_at is None or now >= _stored_rotation_time(
                grace_expires_at,
                code="scim_directory_rotation_state_invalid",
            ):
                raise LifecycleError("scim_authentication_failed", "SCIM credential is invalid")
        apply_rls_context(
            db,
            RlsContext(tenant_id=directory.tenant_id, scim_token_hash=token_hash),
        )
        return directory

    @classmethod
    def _validate_list_request(
        cls,
        *,
        start_index: int,
        count: int,
        filter_attribute: str | None,
        filter_value: str | None,
        filter_expression: ScimFilterExpression | None,
        resource_type: str,
        sort_by: str | None,
        sort_order: str,
    ) -> ScimFilterExpression | None:
        if start_index < 1 or count < 0 or count > 100:
            raise LifecycleError("invalidValue", "SCIM pagination is invalid")
        if (filter_attribute is None) != (filter_value is None):
            raise LifecycleError("invalidFilter", "SCIM filter is invalid")
        if filter_expression is not None and filter_attribute is not None:
            raise LifecycleError("invalidFilter", "SCIM filter is ambiguous")
        resolved = filter_expression
        if filter_attribute is not None:
            raw_value = str(filter_value)
            value: str | bool = raw_value
            if filter_attribute == "active":
                value = cls._filter_boolean(raw_value)
            resolved = ScimFilterExpression(
                operator="eq",
                attribute=filter_attribute,
                value=value,
            )
        if resolved is not None:
            term_count = cls._validate_filter_expression(
                resolved,
                resource_type=resource_type,
                depth=0,
            )
            if term_count > 16:
                raise LifecycleError("invalidFilter", "SCIM filter has too many terms")
        allowed_sort = {
            "User": {"id", "externalId", "userName", "displayName", "active"},
            "Group": {"id", "externalId", "displayName", "active"},
        }[resource_type]
        if sort_by is not None and sort_by not in allowed_sort:
            raise LifecycleError("invalidValue", "SCIM sort attribute is unsupported")
        if sort_order not in {"ascending", "descending"}:
            raise LifecycleError("invalidValue", "SCIM sort order is invalid")
        if sort_by is None and sort_order != "ascending":
            raise LifecycleError("invalidValue", "SCIM sortBy is required for sortOrder")
        return resolved

    @classmethod
    def _validate_filter_expression(
        cls,
        expression: ScimFilterExpression,
        *,
        resource_type: str,
        depth: int,
    ) -> int:
        if depth > 16:
            raise LifecycleError("invalidFilter", "SCIM filter nesting is too deep")
        operator = expression.operator
        if operator in {"and", "or"}:
            if (
                expression.attribute is not None
                or expression.value is not None
                or len(expression.operands) != 2
                or expression.schema is not None
                or expression.sub_attribute is not None
            ):
                raise LifecycleError("invalidFilter", "SCIM logical filter is invalid")
            return sum(
                cls._validate_filter_expression(
                    operand,
                    resource_type=resource_type,
                    depth=depth + 1,
                )
                for operand in expression.operands
            )
        if operator == "not":
            if (
                expression.attribute is not None
                or expression.value is not None
                or len(expression.operands) != 1
                or expression.schema is not None
                or expression.sub_attribute is not None
            ):
                raise LifecycleError("invalidFilter", "SCIM not filter is invalid")
            return cls._validate_filter_expression(
                expression.operands[0],
                resource_type=resource_type,
                depth=depth + 1,
            )
        if operator == "valuePath":
            attribute, sub_attribute = cls._resolved_filter_attribute(
                expression,
                resource_type=resource_type,
            )
            if (
                resource_type != "Group"
                or attribute != "members"
                or sub_attribute is not None
                or expression.value is not None
                or len(expression.operands) != 1
            ):
                raise LifecycleError("invalidFilter", "SCIM valuePath is unsupported")
            return cls._validate_member_filter_expression(expression.operands[0], depth=depth + 1)

        if expression.operands:
            raise LifecycleError("invalidFilter", "SCIM comparison filter is invalid")
        attribute, sub_attribute = cls._resolved_filter_attribute(
            expression,
            resource_type=resource_type,
        )
        if attribute == "members":
            if resource_type != "Group":
                raise LifecycleError("invalidFilter", "SCIM filter attribute is unsupported")
            if sub_attribute is None:
                if operator == "pr" and expression.value is None:
                    return 1
                raise LifecycleError("invalidFilter", "SCIM members filter requires value")
            return cls._validate_member_filter_expression(
                ScimFilterExpression(
                    operator=operator,
                    attribute=sub_attribute,
                    value=expression.value,
                ),
                depth=depth + 1,
            )
        if operator == "pr":
            if expression.value is not None:
                raise LifecycleError("invalidFilter", "SCIM presence filter is invalid")
            return 1
        value = expression.value
        if attribute == "active":
            if operator not in {"eq", "ne"} or type(value) is not bool:
                raise LifecycleError("invalidFilter", "SCIM Boolean filter is invalid")
            return 1
        if value is None:
            if operator not in {"eq", "ne"}:
                raise LifecycleError("invalidFilter", "SCIM null filter is invalid")
            return 1
        if not isinstance(value, str) or len(value) > 320:
            raise LifecycleError("invalidFilter", "SCIM filter value is invalid")
        if attribute == "id":
            if operator not in {"eq", "ne"}:
                raise LifecycleError("invalidFilter", "SCIM id filter operator is unsupported")
            try:
                UUID(value)
            except ValueError as error:
                raise LifecycleError("invalidFilter", "SCIM filter value is invalid") from error
            return 1
        if operator not in {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}:
            raise LifecycleError("invalidFilter", "SCIM filter operator is unsupported")
        if attribute == "userName" and operator in {"eq", "ne"}:
            try:
                _normalize_user_name(value)
            except LifecycleError as error:
                raise LifecycleError("invalidFilter", "SCIM filter value is invalid") from error
        return 1

    @staticmethod
    def _resolved_filter_attribute(
        expression: ScimFilterExpression,
        *,
        resource_type: str,
    ) -> tuple[str, str | None]:
        if (
            expression.schema is not None
            and expression.schema.casefold() != expected_core_schema(resource_type).casefold()
        ):
            raise LifecycleError("invalidFilter", "SCIM filter schema does not match resource")
        attribute_map = {
            "User": {
                "id": "id",
                "externalid": "externalId",
                "username": "userName",
                "displayname": "displayName",
                "active": "active",
            },
            "Group": {
                "id": "id",
                "externalid": "externalId",
                "displayname": "displayName",
                "active": "active",
                "members": "members",
            },
        }[resource_type]
        raw_attribute = expression.attribute
        attribute = (
            attribute_map.get(raw_attribute.casefold()) if isinstance(raw_attribute, str) else None
        )
        if attribute is None:
            raise LifecycleError("invalidFilter", "SCIM filter attribute is unsupported")
        raw_sub_attribute = expression.sub_attribute
        if raw_sub_attribute is None:
            return attribute, None
        if attribute != "members" or raw_sub_attribute.casefold() != "value":
            raise LifecycleError("invalidFilter", "SCIM filter sub-attribute is unsupported")
        return attribute, "value"

    @classmethod
    def _validate_member_filter_expression(
        cls,
        expression: ScimFilterExpression,
        *,
        depth: int,
    ) -> int:
        if depth > 16 or expression.schema is not None:
            raise LifecycleError("invalidFilter", "SCIM member filter is invalid")
        if expression.operator in {"and", "or"}:
            if (
                expression.attribute is not None
                or expression.value is not None
                or expression.sub_attribute is not None
                or len(expression.operands) != 2
            ):
                raise LifecycleError("invalidFilter", "SCIM member filter is invalid")
            return sum(
                cls._validate_member_filter_expression(item, depth=depth + 1)
                for item in expression.operands
            )
        if expression.operator == "not":
            if (
                expression.attribute is not None
                or expression.value is not None
                or expression.sub_attribute is not None
                or len(expression.operands) != 1
            ):
                raise LifecycleError("invalidFilter", "SCIM member filter is invalid")
            return cls._validate_member_filter_expression(expression.operands[0], depth=depth + 1)
        if (
            expression.operator == "valuePath"
            or expression.operands
            or expression.sub_attribute is not None
            or (expression.attribute or "").casefold() != "value"
        ):
            raise LifecycleError("invalidFilter", "SCIM member filter is unsupported")
        if expression.operator == "pr":
            if expression.value is not None:
                raise LifecycleError("invalidFilter", "SCIM member presence filter is invalid")
            return 1
        if expression.value is None:
            if expression.operator not in {"eq", "ne"}:
                raise LifecycleError("invalidFilter", "SCIM member null filter is invalid")
            return 1
        if not isinstance(expression.value, str) or len(expression.value) > 320:
            raise LifecycleError("invalidFilter", "SCIM member filter value is invalid")
        if expression.operator not in {
            "eq",
            "ne",
            "co",
            "sw",
            "ew",
            "gt",
            "ge",
            "lt",
            "le",
        }:
            raise LifecycleError("invalidFilter", "SCIM member filter operator is unsupported")
        return 1

    @classmethod
    def _filter_predicate(
        cls,
        expression: ScimFilterExpression,
        *,
        resource_type: str,
    ) -> sa.ColumnElement[bool]:
        if expression.operator == "and":
            return sa.and_(
                *(
                    cls._filter_predicate(operand, resource_type=resource_type)
                    for operand in expression.operands
                )
            )
        if expression.operator == "or":
            return sa.or_(
                *(
                    cls._filter_predicate(operand, resource_type=resource_type)
                    for operand in expression.operands
                )
            )
        if expression.operator == "not":
            return sa.not_(
                cls._filter_predicate(expression.operands[0], resource_type=resource_type)
            )
        if expression.operator == "valuePath":
            return cls._member_exists_predicate(expression.operands[0])
        attribute, sub_attribute = cls._resolved_filter_attribute(
            expression,
            resource_type=resource_type,
        )
        if attribute == "members":
            if sub_attribute is None:
                return cls._member_exists_predicate(
                    ScimFilterExpression(operator="pr", attribute="value")
                )
            return cls._member_exists_predicate(
                ScimFilterExpression(
                    operator=expression.operator,
                    attribute=sub_attribute,
                    value=expression.value,
                )
            )
        column = cls._filter_column(resource_type=resource_type, attribute=attribute)
        if expression.operator == "pr":
            return column.is_not(None)
        value = expression.value
        if value is None:
            return column.is_(None) if expression.operator == "eq" else column.is_not(None)
        if attribute == "id":
            predicate = column == UUID(cast(str, value))
        elif attribute == "active":
            predicate = column == cast(bool, value)
        else:
            text_value = cast(str, value)
            comparison_column = column
            if attribute in {"userName", "displayName"}:
                comparison_column = sa.func.lower(column)
                text_value = text_value.casefold()
            if attribute == "userName" and expression.operator in {"eq", "ne"}:
                text_value = _normalize_user_name(text_value)
            if expression.operator in {"eq", "ne"}:
                predicate = comparison_column == text_value
            elif expression.operator == "co":
                predicate = comparison_column.contains(text_value, autoescape=True)
            elif expression.operator == "sw":
                predicate = comparison_column.startswith(text_value, autoescape=True)
            elif expression.operator == "ew":
                predicate = comparison_column.endswith(text_value, autoescape=True)
            elif expression.operator == "gt":
                predicate = comparison_column > text_value
            elif expression.operator == "ge":
                predicate = comparison_column >= text_value
            elif expression.operator == "lt":
                predicate = comparison_column < text_value
            else:
                predicate = comparison_column <= text_value
        if expression.operator == "ne":
            predicate = sa.not_(predicate)
        return sa.func.coalesce(predicate, sa.false())

    @classmethod
    def _member_exists_predicate(
        cls,
        expression: ScimFilterExpression,
    ) -> sa.ColumnElement[bool]:
        membership = aliased(EnterpriseGroupMembershipRecord)
        user = aliased(EnterpriseScimUserRecord)
        member_predicate = cls._member_value_predicate(expression, user=user)
        return sa.exists(
            sa.select(1)
            .select_from(membership)
            .join(
                user,
                sa.and_(
                    user.tenant_id == membership.tenant_id,
                    user.user_id == membership.user_id,
                ),
            )
            .where(
                membership.tenant_id == EnterpriseScimGroupRecord.tenant_id,
                membership.group_id == EnterpriseScimGroupRecord.enterprise_group_id,
                membership.status == "active",
                user.directory_id == EnterpriseScimGroupRecord.directory_id,
                user.active.is_(True),
                member_predicate,
            )
            .correlate(EnterpriseScimGroupRecord)
        )

    @classmethod
    def _member_value_predicate(
        cls,
        expression: ScimFilterExpression,
        *,
        user: Any,
    ) -> sa.ColumnElement[bool]:
        if expression.operator == "and":
            return sa.and_(
                *(cls._member_value_predicate(item, user=user) for item in expression.operands)
            )
        if expression.operator == "or":
            return sa.or_(
                *(cls._member_value_predicate(item, user=user) for item in expression.operands)
            )
        if expression.operator == "not":
            return sa.not_(cls._member_value_predicate(expression.operands[0], user=user))
        if expression.operator == "pr":
            return user.id.is_not(None)
        if expression.value is None:
            return sa.false() if expression.operator == "eq" else sa.true()
        text_value = cast(str, expression.value).casefold()
        if expression.operator in {"eq", "ne"}:
            try:
                predicate = user.id == UUID(text_value)
            except ValueError:
                predicate = sa.false()
            return sa.not_(predicate) if expression.operator == "ne" else predicate
        comparison_column = sa.func.replace(
            sa.func.lower(sa.cast(user.id, sa.String())),
            "-",
            "",
        )
        text_value = text_value.replace("-", "")
        if expression.operator == "co":
            predicate = comparison_column.contains(text_value, autoescape=True)
        elif expression.operator == "sw":
            predicate = comparison_column.startswith(text_value, autoescape=True)
        elif expression.operator == "ew":
            predicate = comparison_column.endswith(text_value, autoescape=True)
        elif expression.operator == "gt":
            predicate = comparison_column > text_value
        elif expression.operator == "ge":
            predicate = comparison_column >= text_value
        elif expression.operator == "lt":
            predicate = comparison_column < text_value
        else:
            predicate = comparison_column <= text_value
        return predicate

    @staticmethod
    def _filter_column(*, resource_type: str, attribute: str) -> sa.ColumnElement[Any]:
        if resource_type == "User":
            return cast(
                sa.ColumnElement[Any],
                {
                    "id": EnterpriseScimUserRecord.id,
                    "externalId": EnterpriseScimUserRecord.external_id,
                    "userName": EnterpriseScimUserRecord.user_name_normalized,
                    "displayName": EnterpriseScimUserRecord.display_name,
                    "active": EnterpriseScimUserRecord.active,
                }[attribute],
            )
        return cast(
            sa.ColumnElement[Any],
            {
                "id": EnterpriseScimGroupRecord.id,
                "externalId": EnterpriseScimGroupRecord.external_id,
                "displayName": EnterpriseScimGroupRecord.display_name,
                "active": EnterpriseScimGroupRecord.active,
            }[attribute],
        )

    @classmethod
    def _sort_expressions(
        cls,
        *,
        resource_type: str,
        sort_by: str | None,
        sort_order: str,
    ) -> tuple[sa.ColumnElement[Any], ...]:
        id_column = cls._filter_column(resource_type=resource_type, attribute="id")
        if sort_by is None or sort_by == "id":
            return (id_column.desc() if sort_order == "descending" else id_column.asc(),)
        column = cls._filter_column(resource_type=resource_type, attribute=sort_by)
        comparison_column = (
            sa.func.lower(column) if sort_by in {"userName", "displayName"} else column
        )
        primary = (
            comparison_column.desc() if sort_order == "descending" else comparison_column.asc()
        )
        if sort_by == "displayName":
            missing_value_order = (
                column.is_(None).desc() if sort_order == "descending" else column.is_(None).asc()
            )
            return (missing_value_order, primary, id_column.asc())
        return (primary, id_column.asc())

    @staticmethod
    def _filter_boolean(value: str) -> bool:
        normalized = value.casefold()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
        raise LifecycleError("invalidFilter", "SCIM Boolean filter is invalid")

    def _user_view(
        self,
        db: Session,
        *,
        directory: EnterpriseScimDirectoryRecord,
        user: EnterpriseScimUserRecord,
    ) -> ScimUserView:
        membership = (
            db.get(TenantMembership, (directory.tenant_id, user.user_id))
            if user.user_id is not None
            else None
        )
        result = self._user_payload(
            db,
            user,
            disposition="applied",
            requires_owner_recovery=bool(
                not user.active
                and membership is not None
                and membership.role == "owner"
                and membership.status == "suspended"
            ),
            revoked_session_count=0,
        )
        return self._user_result(result)

    @staticmethod
    def _apply_request_context(db: Session, request: RequestContext) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
            ),
        )

    @staticmethod
    def _require_manage(db: Session, request: RequestContext) -> None:
        membership = db.get(TenantMembership, (request.tenant_id, request.actor_id))
        if (
            membership is None
            or membership.status != "active"
            or "enterprise_identity.manage" not in TENANT_ROLE_PERMISSIONS[membership.role]
        ):
            raise LifecycleError(
                "enterprise_identity_manage_forbidden",
                "enterprise identity management permission is required",
            )

    @staticmethod
    def _create_global_user(db: Session, user_name: str, display_name: str | None) -> GlobalUser:
        user = GlobalUser(
            id=uuid4(),
            status="active",
            display_name=display_name,
            primary_email_normalized=user_name if "@" in user_name else None,
            security_version=1,
        )
        db.add(user)
        db.flush()
        return user

    @staticmethod
    def _deprovision_user(
        db: Session, tenant_id: UUID, user_id: UUID, now: datetime
    ) -> tuple[bool, int]:
        membership = db.get(TenantMembership, (tenant_id, user_id))
        requires_owner_recovery = membership is not None and membership.role == "owner"
        if membership is not None:
            membership.status = "suspended" if requires_owner_recovery else "removed"
            membership.version += 1
        db.execute(
            sa.update(SpaceMembership)
            .where(
                SpaceMembership.tenant_id == tenant_id,
                SpaceMembership.user_id == user_id,
                SpaceMembership.status != "removed",
            )
            .values(status="removed", version=SpaceMembership.version + 1)
        )
        db.execute(
            sa.update(ProjectMembershipRecord)
            .where(
                ProjectMembershipRecord.tenant_id == tenant_id,
                ProjectMembershipRecord.subject_type == "user",
                ProjectMembershipRecord.subject_id == user_id,
                ProjectMembershipRecord.status != "revoked",
            )
            .values(status="revoked", version=ProjectMembershipRecord.version + 1)
        )
        db.execute(
            sa.update(ResourceGrantRecord)
            .where(
                ResourceGrantRecord.tenant_id == tenant_id,
                ResourceGrantRecord.subject_type == "user",
                ResourceGrantRecord.subject_id == user_id,
                ResourceGrantRecord.status == "active",
            )
            .values(status="revoked", version=ResourceGrantRecord.version + 1)
        )
        db.execute(
            sa.update(EnterpriseGroupMembershipRecord)
            .where(
                EnterpriseGroupMembershipRecord.tenant_id == tenant_id,
                EnterpriseGroupMembershipRecord.user_id == user_id,
                EnterpriseGroupMembershipRecord.status == "active",
            )
            .values(status="removed", version=EnterpriseGroupMembershipRecord.version + 1)
        )
        revoked = cast(
            CursorResult[tuple[object]],
            db.execute(
                sa.update(AuthSessionRecord)
                .where(
                    AuthSessionRecord.user_id == user_id,
                    AuthSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            ),
        ).rowcount
        global_user = db.get(GlobalUser, user_id)
        if global_user is not None:
            global_user.security_version += 1
        return requires_owner_recovery, int(revoked or 0)

    @staticmethod
    def _current_group_member_external_ids(
        db: Session,
        *,
        directory: EnterpriseScimDirectoryRecord,
        group: EnterpriseScimGroupRecord,
    ) -> tuple[str, ...]:
        return tuple(
            db.scalars(
                sa.select(EnterpriseScimUserRecord.external_id)
                .join(
                    EnterpriseGroupMembershipRecord,
                    sa.and_(
                        EnterpriseGroupMembershipRecord.tenant_id
                        == EnterpriseScimUserRecord.tenant_id,
                        EnterpriseGroupMembershipRecord.user_id
                        == EnterpriseScimUserRecord.user_id,
                    ),
                )
                .where(
                    EnterpriseGroupMembershipRecord.tenant_id == directory.tenant_id,
                    EnterpriseGroupMembershipRecord.group_id == group.enterprise_group_id,
                    EnterpriseGroupMembershipRecord.status == "active",
                    EnterpriseScimUserRecord.directory_id == directory.id,
                    EnterpriseScimUserRecord.active.is_(True),
                )
                .order_by(EnterpriseScimUserRecord.external_id)
            )
        )

    @staticmethod
    def _converge_group_members(
        db: Session,
        *,
        directory: EnterpriseScimDirectoryRecord,
        group: EnterpriseScimGroupRecord,
        desired_external_ids: tuple[str, ...],
    ) -> tuple[str, ...]:
        users = db.execute(
            sa.select(EnterpriseScimUserRecord).where(
                EnterpriseScimUserRecord.directory_id == directory.id,
                EnterpriseScimUserRecord.external_id.in_(desired_external_ids or ("",)),
            )
        ).scalars()
        by_external = {user.external_id: user for user in users}
        desired_user_ids: set[UUID] = set()
        blocked: list[str] = []
        for external_id in desired_external_ids:
            user = by_external.get(external_id)
            if user is None or not user.active or user.user_id is None:
                blocked.append(external_id)
            else:
                desired_user_ids.add(user.user_id)

        existing = {
            membership.user_id: membership
            for membership in db.execute(
                sa.select(EnterpriseGroupMembershipRecord).where(
                    EnterpriseGroupMembershipRecord.tenant_id == directory.tenant_id,
                    EnterpriseGroupMembershipRecord.group_id == group.enterprise_group_id,
                )
            ).scalars()
        }
        for user_id, membership in existing.items():
            if user_id not in desired_user_ids and membership.status == "active":
                membership.status = "removed"
                membership.version += 1
        for user_id in desired_user_ids:
            membership = existing.get(user_id)
            if membership is None:
                db.add(
                    EnterpriseGroupMembershipRecord(
                        tenant_id=directory.tenant_id,
                        group_id=group.enterprise_group_id,
                        user_id=user_id,
                        status="active",
                        version=1,
                        created_by=directory.configured_by,
                    )
                )
            elif membership.status != "active":
                membership.status = "active"
                membership.version += 1
        return tuple(blocked)

    @staticmethod
    def _event_replay(
        db: Session, directory_id: UUID, event_id: str, request_hash: str
    ) -> EnterpriseScimEventRecord | None:
        event = db.execute(
            sa.select(EnterpriseScimEventRecord).where(
                EnterpriseScimEventRecord.directory_id == directory_id,
                EnterpriseScimEventRecord.event_id == event_id,
            )
        ).scalar_one_or_none()
        if event is not None and event.request_hash != request_hash:
            raise LifecycleError("scim_event_conflict", "SCIM event ID has a different request")
        if event is not None and event.redacted_at is not None:
            raise LifecycleError(
                "scim_subject_deleted", "redacted SCIM receipts cannot be replayed"
            )
        return event

    @staticmethod
    def _record_event(
        db: Session,
        directory: EnterpriseScimDirectoryRecord,
        event_id: str,
        request_hash: str,
        resource_type: str,
        resource_id: UUID,
        source_version: int,
        disposition: str,
        result: dict[str, object],
        *,
        event_type: str | None = None,
    ) -> None:
        db.add(
            EnterpriseScimEventRecord(
                id=uuid4(),
                tenant_id=directory.tenant_id,
                directory_id=directory.id,
                event_id=event_id,
                resource_type=resource_type,
                resource_id=resource_id,
                source_version=source_version,
                request_hash=request_hash,
                disposition=disposition,
                result=result,
            )
        )
        db.add(
            ControlPlaneOutboxEvent(
                id=uuid4(),
                tenant_id=directory.tenant_id,
                aggregate_type=f"enterprise_scim_{resource_type.casefold()}",
                aggregate_key=str(resource_id),
                event_type=(
                    event_type or f"enterprise.scim_{resource_type.casefold()}.{disposition}"
                ),
                payload={
                    "directory_id": str(directory.id),
                    "resource_id": str(resource_id),
                    "resource_type": resource_type,
                    "source_version": source_version,
                    "disposition": disposition,
                },
                idempotency_key=f"scim:{directory.id}:{_digest(event_id)[:48]}",
                request_hash=request_hash,
            )
        )

    @staticmethod
    def _issued_directory(
        payload: dict[str, object], *, bearer_token: str | None, replayed: bool
    ) -> IssuedScimDirectory:
        return IssuedScimDirectory(
            id=UUID(str(payload["directory_id"])),
            tenant_id=UUID(str(payload["tenant_id"])),
            display_name=str(payload["display_name"]),
            token_prefix=str(payload["token_prefix"]),
            successor_token_prefix=(
                str(payload["successor_token_prefix"])
                if payload.get("successor_token_prefix") is not None
                else None
            ),
            rotation_activates_at=_optional_datetime(payload, "rotation_activates_at"),
            rotation_grace_expires_at=_optional_datetime(
                payload,
                "rotation_grace_expires_at",
            ),
            status=str(payload["status"]),
            version=_integer(payload, "version"),
            bearer_token=bearer_token,
            replayed=replayed,
        )

    @staticmethod
    def _user_payload(
        db: Session,
        user: EnterpriseScimUserRecord,
        *,
        disposition: str,
        requires_owner_recovery: bool,
        revoked_session_count: int,
    ) -> dict[str, object]:
        membership = (
            db.get(TenantMembership, (user.tenant_id, user.user_id))
            if user.user_id is not None
            else None
        )
        return {
            "scim_user_id": str(user.id),
            "directory_id": str(user.directory_id),
            "tenant_id": str(user.tenant_id),
            "user_id": str(user.user_id) if user.user_id else None,
            "external_id": user.external_id,
            "user_name": user.user_name_normalized,
            "display_name": user.display_name,
            "active": user.active,
            "version": user.version,
            "source_version": user.source_version,
            "membership_status": membership.status if membership else None,
            "requires_owner_recovery": requires_owner_recovery,
            "revoked_session_count": revoked_session_count,
            "disposition": disposition,
        }

    @staticmethod
    def _user_result(payload: dict[str, object], replayed: bool = False) -> ScimUserView:
        return ScimUserView(
            id=UUID(str(payload["scim_user_id"])),
            directory_id=UUID(str(payload["directory_id"])),
            tenant_id=UUID(str(payload["tenant_id"])),
            user_id=UUID(str(payload["user_id"])) if payload.get("user_id") else None,
            external_id=str(payload["external_id"]),
            user_name=str(payload["user_name"]),
            display_name=(
                str(payload["display_name"]) if payload.get("display_name") is not None else None
            ),
            active=bool(payload["active"]),
            version=_integer(payload, "version"),
            source_version=_integer(payload, "source_version"),
            membership_status=(
                str(payload["membership_status"])
                if payload.get("membership_status") is not None
                else None
            ),
            requires_owner_recovery=bool(payload["requires_owner_recovery"]),
            revoked_session_count=_integer(payload, "revoked_session_count"),
            disposition=str(payload["disposition"]),
            replayed=replayed,
        )

    @staticmethod
    def _group_payload(
        db: Session,
        group: EnterpriseScimGroupRecord,
        blocked: tuple[str, ...],
        disposition: str,
    ) -> dict[str, object]:
        active_count = db.scalar(
            sa.select(sa.func.count())
            .select_from(EnterpriseGroupMembershipRecord)
            .where(
                EnterpriseGroupMembershipRecord.tenant_id == group.tenant_id,
                EnterpriseGroupMembershipRecord.group_id == group.enterprise_group_id,
                EnterpriseGroupMembershipRecord.status == "active",
            )
        )
        member_scim_user_ids = tuple(
            db.scalars(
                sa.select(EnterpriseScimUserRecord.id)
                .join(
                    EnterpriseGroupMembershipRecord,
                    sa.and_(
                        EnterpriseGroupMembershipRecord.tenant_id
                        == EnterpriseScimUserRecord.tenant_id,
                        EnterpriseGroupMembershipRecord.user_id
                        == EnterpriseScimUserRecord.user_id,
                    ),
                )
                .where(
                    EnterpriseGroupMembershipRecord.tenant_id == group.tenant_id,
                    EnterpriseGroupMembershipRecord.group_id == group.enterprise_group_id,
                    EnterpriseGroupMembershipRecord.status == "active",
                    EnterpriseScimUserRecord.directory_id == group.directory_id,
                    EnterpriseScimUserRecord.active.is_(True),
                )
                .order_by(EnterpriseScimUserRecord.id)
            )
        )
        return {
            "scim_group_id": str(group.id),
            "directory_id": str(group.directory_id),
            "tenant_id": str(group.tenant_id),
            "enterprise_group_id": str(group.enterprise_group_id),
            "external_id": group.external_id,
            "display_name": group.display_name,
            "active": group.active,
            "version": group.version,
            "source_version": group.source_version,
            "active_member_count": int(active_count or 0),
            "member_scim_user_ids": [str(item) for item in member_scim_user_ids],
            "blocked_external_ids": list(blocked),
            "disposition": disposition,
        }

    @staticmethod
    def _group_result(payload: dict[str, object], replayed: bool = False) -> ScimGroupView:
        raw_blocked = payload.get("blocked_external_ids")
        blocked = tuple(str(item) for item in raw_blocked) if isinstance(raw_blocked, list) else ()
        raw_members = payload.get("member_scim_user_ids")
        member_ids = (
            tuple(UUID(str(item)) for item in raw_members) if isinstance(raw_members, list) else ()
        )
        return ScimGroupView(
            id=UUID(str(payload["scim_group_id"])),
            directory_id=UUID(str(payload["directory_id"])),
            tenant_id=UUID(str(payload["tenant_id"])),
            enterprise_group_id=UUID(str(payload["enterprise_group_id"])),
            external_id=str(payload["external_id"]),
            display_name=str(payload["display_name"]),
            active=bool(payload["active"]),
            version=_integer(payload, "version"),
            source_version=_integer(payload, "source_version"),
            active_member_count=_integer(payload, "active_member_count"),
            member_scim_user_ids=member_ids,
            blocked_external_ids=blocked,
            disposition=str(payload["disposition"]),
            replayed=replayed,
        )
