"""Machine-native project and Run operations for the stable public API."""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID

import sqlalchemy as sa
from pydantic import JsonValue
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
from saas.control_plane.api_credentials import ValidatedApiCredential
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    ProjectRecord,
    Space,
    Tenant,
)
from saas.control_plane.execution_models import (
    TERMINAL_RUN_STATUSES,
    AdmissionQuotaRecord,
    ExecutionSessionRecord,
    QuotaReservationRecord,
    RunEventRecord,
    RunRecord,
    SessionTaskRecord,
    TaskRecord,
)
from saas.control_plane.permissions import PERMISSION_CATALOG
from saas.control_plane.public_api_models import (
    PublicApiMutationReceiptRecord,
    PublicApiRateLimitRecord,
)
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.public_api_contract import CursorError, FilterBoundCursorCodec

_LEASED_STATUSES = frozenset(
    {"leased", "starting", "running", "waiting_input", "waiting_approval", "cancelling"}
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_hash(payload: dict[str, object]) -> str:
    try:
        encoded = json.dumps(
            payload,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as error:
        raise PublicApiError("request_invalid", "Request contains invalid JSON") from error
    return sha256(encoded.encode()).hexdigest()


def _text(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise PublicApiError(f"{field}_invalid", f"{field} is invalid")
    return cleaned


class PublicApiError(RuntimeError):
    """Stable, content-blind public API failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


@dataclass(frozen=True, slots=True)
class PublicApiProjectView:
    id: UUID
    tenant_id: UUID
    space_id: UUID
    name: str
    visibility: str
    status: str
    authorization_version: int
    created_at: datetime
    updated_at: datetime

    @property
    def etag(self) -> str:
        return f'W/"{self.authorization_version}"'


@dataclass(frozen=True, slots=True)
class PublicApiRunView:
    id: UUID
    task_id: UUID
    session_id: UUID | None
    parent_run_id: UUID | None
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    status: str
    version: int
    event_sequence: int
    queue_class: str
    priority: int
    metadata: dict[str, object]
    created_by_user_id: UUID | None
    created_by_service_account_id: UUID | None
    terminal_at: datetime | None
    created_at: datetime
    updated_at: datetime
    replayed: bool = False

    @property
    def etag(self) -> str:
        return f'W/"{self.version}"'


@dataclass(frozen=True, slots=True)
class PublicApiRunContentView:
    run_id: UUID
    input: dict[str, object]
    product_revision: str
    upstream_revision: str
    schema_revision: str
    adapter_contract_version: str
    etag: str


@dataclass(frozen=True, slots=True)
class PublicApiRunEventView:
    id: UUID
    run_id: UUID
    sequence: int
    event_type: str
    trace_id: str
    created_at: datetime
    payload: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class PublicApiPage:
    items: tuple[object, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class PublicApiRateLimitView:
    limit: int
    remaining: int
    reset_at: datetime

    @property
    def reset_epoch(self) -> int:
        return int(self.reset_at.timestamp())


class PublicApiIdempotencyKeyring:
    """Rotatable receipt keyring isolated from the cursor cryptographic domain."""

    def __init__(self, *, keys: Mapping[str, bytes], active_key_id: str) -> None:
        copied = dict(keys)
        if active_key_id not in copied or not active_key_id or len(active_key_id) > 16:
            raise ValueError("active idempotency key id is invalid")
        if any(not key_id or len(key_id) > 16 for key_id in copied):
            raise ValueError("idempotency key id is invalid")
        if any(len(secret) < 32 for secret in copied.values()):
            raise ValueError("idempotency HMAC keys must contain at least 32 bytes")
        self._keys = copied
        self._active_key_id = active_key_id

    def active_digest(self, value: str) -> tuple[str, str]:
        return self._active_key_id, self._digest(self._active_key_id, value)

    def candidate_digests(self, value: str) -> tuple[tuple[str, str], ...]:
        return tuple((key_id, self._digest(key_id, value)) for key_id in self._keys)

    def _digest(self, key_id: str, value: str) -> str:
        cleaned = _text(value, "idempotency_key", 128)
        message = b"omnigent-public-api-idempotency-v1\0" + cleaned.encode()
        return hmac.new(self._keys[key_id], message, sha256).hexdigest()


class PublicApiExecutionService:
    """Revalidate machine authority and mutate execution facts in one transaction."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        cursor_codec: FilterBoundCursorCodec,
        idempotency_keys: Mapping[str, bytes],
        active_idempotency_key_id: str,
        product_revision: str,
        upstream_revision: str,
        schema_revision: str,
        adapter_contract_version: str,
        rate_limits: Mapping[str, tuple[int, timedelta]] | None = None,
    ) -> None:
        self._sessions = session_factory
        self._cursors = cursor_codec
        self._idempotency = PublicApiIdempotencyKeyring(
            keys=idempotency_keys,
            active_key_id=active_idempotency_key_id,
        )
        self._product_revision = _text(product_revision, "product_revision", 64)
        self._upstream_revision = _text(upstream_revision, "upstream_revision", 64)
        self._schema_revision = _text(schema_revision, "schema_revision", 64)
        self._adapter_contract_version = _text(
            adapter_contract_version, "adapter_contract_version", 32
        )
        configured_limits = dict(
            rate_limits
            or {
                "projects.read": (300, timedelta(minutes=1)),
                "runs.read": (600, timedelta(minutes=1)),
                "runs.write": (120, timedelta(minutes=1)),
                "events.read": (600, timedelta(minutes=1)),
            }
        )
        for route_class, (limit, window) in configured_limits.items():
            _text(route_class, "route_class", 64)
            if limit <= 0 or window <= timedelta(0) or window > timedelta(days=1):
                raise ValueError("public API rate limit policy is invalid")
        self._rate_limits = configured_limits

    def consume_rate_limit(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        permission: str,
        route_class: str,
        now: datetime | None = None,
    ) -> PublicApiRateLimitView:
        """Atomically consume one shared fixed-window request allowance."""

        policy = self._rate_limits.get(route_class)
        if policy is None:
            raise PublicApiError("rate_limit_policy_missing", "rate limit policy is unavailable")
        limit, window = policy
        checked_at = _aware(now or _now())
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db,
                principal,
                project_id=project_id,
                permission=permission,
                checked_at=checked_at,
            )
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:rate_limit_key, 0))"),
                    {
                        "rate_limit_key": (
                            f"public-api-rate:{principal.credential_id}:{route_class}"
                        )
                    },
                )
            record = db.scalar(
                sa.select(PublicApiRateLimitRecord)
                .where(
                    PublicApiRateLimitRecord.credential_id == principal.credential_id,
                    PublicApiRateLimitRecord.route_class == route_class,
                )
                .with_for_update()
            )
            if record is None:
                record = PublicApiRateLimitRecord(
                    tenant_id=principal.tenant_id,
                    credential_id=principal.credential_id,
                    route_class=route_class,
                    window_started_at=checked_at,
                    request_count=1,
                    version=1,
                )
                db.add(record)
            else:
                started = _aware(record.window_started_at)
                if checked_at >= started + window:
                    record.window_started_at = checked_at
                    record.request_count = 1
                else:
                    record.request_count += 1
                record.version += 1
            reset_at = _aware(record.window_started_at) + window
            if record.request_count > limit:
                retry_after = max(1, int((reset_at - checked_at).total_seconds()))
                raise PublicApiError(
                    "rate_limit_exceeded",
                    "Shared API rate limit exceeded",
                    details={
                        "limit": limit,
                        "remaining": 0,
                        "reset": int(reset_at.timestamp()),
                        "retry_after": retry_after,
                    },
                )
            return PublicApiRateLimitView(
                limit,
                max(0, limit - record.request_count),
                reset_at,
            )

    def list_projects(
        self,
        principal: ValidatedApiCredential,
        *,
        cursor: str | None,
        limit: int,
        status: str | None = None,
    ) -> PublicApiPage:
        if not 1 <= limit <= 100:
            raise PublicApiError("page_limit_invalid", "limit must be between 1 and 100")
        project_id = self._bound_project_id(principal)
        if status is not None and status not in {"active", "suspended", "archived"}:
            raise PublicApiError("status_invalid", "status is invalid")
        scope = f"{principal.tenant_id}:{principal.space_id}"
        filters: dict[str, JsonValue] = {"status": status}
        after_created_at: datetime | None = None
        after_id: UUID | None = None
        if cursor is not None:
            try:
                state = self._cursors.decode(
                    cursor,
                    resource="projects",
                    scope=scope,
                    filters=filters,
                    sort=("created_at", "id"),
                )
            except CursorError as error:
                raise PublicApiError("cursor_invalid", "cursor is invalid") from error
            values = cast(dict[str, object], state.position)
            after_created_at = self._datetime_value(values, "created_at")
            after_id = self._uuid_value(values, "project_id")
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="project.read_metadata"
            )
            project = self._project(db, principal, project_id)
            items: tuple[object, ...] = ()
            if (
                after_created_at is None
                or after_id is None
                or (_aware(project.created_at), project.id) > (after_created_at, after_id)
            ) and (status is None or project.status == status):
                items = (self._project_view(project),)
            return PublicApiPage(items[:limit], None)

    def get_project(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
    ) -> PublicApiProjectView:
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="project.read_metadata"
            )
            return self._project_view(self._project(db, principal, project_id))

    def create_run(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        title: str,
        input_payload: dict[str, object],
        session_id: UUID | None,
        metadata: dict[str, object],
        idempotency_key: str,
        trace_id: str,
        queue_class: str = "interactive",
        priority: int = 0,
        quota_resource: str = "run",
        quota_units: int = 1,
    ) -> PublicApiRunView:
        clean_title = _text(title, "title", 256)
        clean_trace = _text(trace_id, "trace_id", 128)
        clean_queue = _text(queue_class, "queue_class", 64)
        clean_resource = _text(quota_resource, "quota_resource", 64)
        if quota_units <= 0:
            raise PublicApiError("quota_units_invalid", "quota_units must be positive")
        stored_key = self._active_stored_run_key(
            principal.credential_id,
            operation="run.create",
            idempotency_key=idempotency_key,
        )
        candidate_keys = self._stored_run_keys(
            principal.credential_id,
            operation="run.create",
            idempotency_key=idempotency_key,
        )
        request_payload: dict[str, object] = {
            "operation": "run.create",
            "credential_id": str(principal.credential_id),
            "service_account_id": str(principal.service_account_id),
            "project_id": str(project_id),
            "title": clean_title,
            "input": input_payload,
            "session_id": str(session_id) if session_id else None,
            "metadata": metadata,
            "queue_class": clean_queue,
            "priority": priority,
            "quota_resource": clean_resource,
            "quota_units": quota_units,
            "revisions": {
                "product": self._product_revision,
                "upstream": self._upstream_revision,
                "schema": self._schema_revision,
                "adapter": self._adapter_contract_version,
            },
        }
        digest = _canonical_hash(request_payload)
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.create"
            )
            if session_id is not None:
                self._require_machine_permission(
                    db,
                    principal,
                    project_id=project_id,
                    permission="run.read_content",
                )
            self._serialize_idempotency(
                db,
                principal,
                operation="run.create",
                idempotency_key=idempotency_key,
            )
            existing = db.scalar(
                sa.select(RunRecord).where(
                    RunRecord.tenant_id == principal.tenant_id,
                    RunRecord.idempotency_key.in_(candidate_keys),
                )
            )
            if existing is not None:
                self._require_replay_match(existing, principal, project_id, digest)
                return self._run_view(existing, replayed=True)
            quota = self._reserve_quota(
                db,
                principal,
                project_id=project_id,
                resource=clean_resource,
                units=quota_units,
            )
            task = TaskRecord(
                tenant_id=principal.tenant_id,
                space_id=cast(UUID, principal.space_id),
                project_id=project_id,
                created_by=None,
                created_by_service_account_id=principal.service_account_id,
                title=clean_title,
                version=1,
            )
            db.add(task)
            db.flush()
            if session_id is not None:
                execution_session = db.scalar(
                    sa.select(ExecutionSessionRecord).where(
                        ExecutionSessionRecord.id == session_id,
                        ExecutionSessionRecord.tenant_id == principal.tenant_id,
                        ExecutionSessionRecord.space_id == principal.space_id,
                        ExecutionSessionRecord.project_id == project_id,
                    )
                )
                if execution_session is None:
                    raise PublicApiError("session_not_found", "Session was not found")
                if execution_session.status != "active":
                    raise PublicApiError("session_closed", "Session is closed")
                db.add(
                    SessionTaskRecord(
                        tenant_id=principal.tenant_id,
                        space_id=cast(UUID, principal.space_id),
                        project_id=project_id,
                        session_id=session_id,
                        task_id=task.id,
                        attached_by=None,
                        attached_by_service_account_id=principal.service_account_id,
                    )
                )
            run = self._new_run(
                principal,
                project_id=project_id,
                task_id=task.id,
                session_id=session_id,
                input_payload=input_payload,
                metadata=metadata,
                stored_key=stored_key,
                request_hash=digest,
                queue_class=clean_queue,
                priority=priority,
            )
            db.add(run)
            db.flush()
            reservation = QuotaReservationRecord(
                tenant_id=principal.tenant_id,
                space_id=cast(UUID, principal.space_id),
                project_id=project_id,
                quota_id=quota.id,
                run_id=run.id,
                units=quota_units,
                status="reserved",
                version=1,
            )
            db.add(reservation)
            db.flush()
            quota.reserved_units += quota_units
            quota.version += 1
            self._append_event(
                db,
                run,
                event_type="run.created",
                payload={
                    "status": "created",
                    "quota_reservation_id": str(reservation.id),
                    "quota_resource": clean_resource,
                    "quota_units": quota_units,
                },
                trace_id=clean_trace,
            )
            run.status = "queued"
            run.version += 1
            self._append_event(
                db,
                run,
                event_type="run.queued",
                payload={"status": "queued", "queue_class": clean_queue, "priority": priority},
                trace_id=clean_trace,
            )
            return self._run_view(run)

    def list_runs(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        cursor: str | None,
        limit: int,
        statuses: tuple[str, ...] = (),
        created_after: datetime | None = None,
        created_before: datetime | None = None,
    ) -> PublicApiPage:
        if not 1 <= limit <= 100:
            raise PublicApiError("page_limit_invalid", "limit must be between 1 and 100")
        allowed_statuses = {
            "created",
            "queued",
            "leased",
            "starting",
            "running",
            "waiting_input",
            "waiting_approval",
            "cancelling",
            "cancelled",
            "succeeded",
            "failed",
            "timed_out",
            "orphaned",
        }
        canonical_statuses = tuple(sorted(set(statuses)))
        if any(status not in allowed_statuses for status in canonical_statuses):
            raise PublicApiError("status_invalid", "status filter is invalid")
        if created_after is not None:
            created_after = _aware(created_after)
        if created_before is not None:
            created_before = _aware(created_before)
        if (
            created_after is not None
            and created_before is not None
            and created_after >= created_before
        ):
            raise PublicApiError("time_range_invalid", "created_at range is invalid")
        scope = f"{principal.tenant_id}:{principal.space_id}:{project_id}"
        filters = cast(
            dict[str, JsonValue],
            {
                "status": list(canonical_statuses),
                "created_after": created_after.isoformat() if created_after else None,
                "created_before": created_before.isoformat() if created_before else None,
            },
        )
        after_created_at: datetime | None = None
        after_id: UUID | None = None
        if cursor is not None:
            try:
                state = self._cursors.decode(
                    cursor,
                    resource="runs",
                    scope=scope,
                    filters=filters,
                    sort=("created_at", "id"),
                )
            except CursorError as error:
                raise PublicApiError("cursor_invalid", "cursor is invalid") from error
            values = cast(dict[str, object], state.position)
            after_created_at = self._datetime_value(values, "created_at")
            after_id = self._uuid_value(values, "run_id")
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.read_metadata"
            )
            query = sa.select(RunRecord).where(
                RunRecord.tenant_id == principal.tenant_id,
                RunRecord.space_id == principal.space_id,
                RunRecord.project_id == project_id,
            )
            if canonical_statuses:
                query = query.where(RunRecord.status.in_(canonical_statuses))
            if created_after is not None:
                query = query.where(RunRecord.created_at > created_after)
            if created_before is not None:
                query = query.where(RunRecord.created_at < created_before)
            if after_created_at is not None and after_id is not None:
                query = query.where(
                    sa.tuple_(RunRecord.created_at, RunRecord.id)
                    > sa.tuple_(sa.literal(after_created_at), sa.literal(after_id))
                )
            rows = tuple(
                db.scalars(query.order_by(RunRecord.created_at, RunRecord.id).limit(limit + 1))
            )
            visible = rows[:limit]
            next_cursor = None
            if len(rows) > limit and visible:
                last = visible[-1]
                next_cursor = self._cursors.encode(
                    resource="runs",
                    scope=scope,
                    filters=filters,
                    sort=("created_at", "id"),
                    position={
                        "created_at": _aware(last.created_at).isoformat(),
                        "run_id": str(last.id),
                    },
                )
            return PublicApiPage(tuple(self._run_view(row) for row in visible), next_cursor)

    def get_run(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        run_id: UUID,
    ) -> PublicApiRunView:
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.read_metadata"
            )
            return self._run_view(self._run(db, principal, project_id, run_id))

    def get_run_content(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        run_id: UUID,
    ) -> PublicApiRunContentView:
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.read_content"
            )
            run = self._run(db, principal, project_id, run_id)
            return PublicApiRunContentView(
                run.id,
                cast(dict[str, object], run.input),
                run.product_revision,
                run.upstream_revision,
                run.schema_revision,
                run.adapter_contract_version,
                f'W/"{run.version}"',
            )

    def cancel_run(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        run_id: UUID,
        reason: str,
        expected_version: int,
        idempotency_key: str,
        trace_id: str,
        now: datetime | None = None,
    ) -> PublicApiRunView:
        clean_reason = _text(reason, "reason", 1024)
        clean_trace = _text(trace_id, "trace_id", 128)
        changed_at = now or _now()
        idempotency_key_id, idempotency_hmac = self._idempotency.active_digest(idempotency_key)
        request_hash = _canonical_hash(
            {
                "operation": "run.cancel",
                "credential_id": str(principal.credential_id),
                "project_id": str(project_id),
                "run_id": str(run_id),
                "reason": clean_reason,
                "expected_version": expected_version,
            }
        )
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.cancel"
            )
            self._serialize_idempotency(
                db,
                principal,
                operation="run.cancel",
                idempotency_key=idempotency_key,
            )
            replay = self._load_receipt(
                db,
                principal,
                operation="run.cancel",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._run_view_from_receipt(replay)
            run = self._run(db, principal, project_id, run_id, lock=True)
            self._require_version(run, expected_version)
            if run.status in TERMINAL_RUN_STATUSES:
                raise PublicApiError("run_terminal", "Run is already terminal")
            if run.status == "cancelling":
                raise PublicApiError("run_cancelling", "Run cancellation is already pending")
            run.cancel_requested_at = changed_at
            if run.status in {"created", "queued"}:
                run.status = "cancelled"
                run.terminal_at = changed_at
                self._finalize_reservations(db, run)
                event_type = "run.cancelled"
            elif run.status in _LEASED_STATUSES:
                run.status = "cancelling"
                event_type = "run.cancelling"
            else:
                raise PublicApiError("run_cancel_invalid", "Run cannot be cancelled")
            run.version += 1
            self._append_event(
                db,
                run,
                event_type=event_type,
                payload={
                    "status": run.status,
                    "reason": clean_reason,
                    "requested_by_service_account_id": str(principal.service_account_id),
                },
                trace_id=clean_trace,
            )
            if run.status == "cancelled":
                self._clear_lease(run)
            view = self._run_view(run)
            db.add(
                PublicApiMutationReceiptRecord(
                    tenant_id=principal.tenant_id,
                    space_id=cast(UUID, principal.space_id),
                    project_id=project_id,
                    service_account_id=principal.service_account_id,
                    credential_id=principal.credential_id,
                    operation="run.cancel",
                    idempotency_key_id=idempotency_key_id,
                    idempotency_hmac=idempotency_hmac,
                    request_hash=request_hash,
                    resource_type="run",
                    resource_id=run.id,
                    response_json=self._run_receipt_payload(view),
                )
            )
            return view

    def retry_run(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        run_id: UUID,
        expected_version: int,
        idempotency_key: str,
        trace_id: str,
        input_override: dict[str, object] | None,
        metadata: dict[str, object],
        queue_class: str | None = None,
        priority: int | None = None,
        quota_resource: str = "run",
        quota_units: int = 1,
    ) -> PublicApiRunView:
        clean_trace = _text(trace_id, "trace_id", 128)
        clean_resource = _text(quota_resource, "quota_resource", 64)
        if quota_units <= 0:
            raise PublicApiError("quota_units_invalid", "quota_units must be positive")
        stored_key = self._active_stored_run_key(
            principal.credential_id,
            operation="run.retry",
            idempotency_key=idempotency_key,
        )
        candidate_keys = self._stored_run_keys(
            principal.credential_id,
            operation="run.retry",
            idempotency_key=idempotency_key,
        )
        request_payload: dict[str, object] = {
            "operation": "run.retry",
            "credential_id": str(principal.credential_id),
            "service_account_id": str(principal.service_account_id),
            "project_id": str(project_id),
            "source_run_id": str(run_id),
            "expected_version": expected_version,
            "input_override": input_override,
            "metadata": metadata,
            "queue_class": queue_class,
            "priority": priority,
            "quota_resource": clean_resource,
            "quota_units": quota_units,
        }
        digest = _canonical_hash(request_payload)
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.retry"
            )
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.create"
            )
            self._serialize_idempotency(
                db,
                principal,
                operation="run.retry",
                idempotency_key=idempotency_key,
            )
            existing = db.scalar(
                sa.select(RunRecord).where(
                    RunRecord.tenant_id == principal.tenant_id,
                    RunRecord.idempotency_key.in_(candidate_keys),
                )
            )
            if existing is not None:
                self._require_replay_match(existing, principal, project_id, digest)
                return self._run_view(existing, replayed=True)
            source = self._run(db, principal, project_id, run_id, lock=True)
            self._require_version(source, expected_version)
            if source.status not in TERMINAL_RUN_STATUSES:
                raise PublicApiError("run_not_terminal", "Only a terminal Run can be retried")
            target_queue = _text(queue_class or source.queue_class, "queue_class", 64)
            target_priority = source.priority if priority is None else priority
            quota = self._reserve_quota(
                db,
                principal,
                project_id=project_id,
                resource=clean_resource,
                units=quota_units,
            )
            run = RunRecord(
                tenant_id=source.tenant_id,
                space_id=source.space_id,
                project_id=source.project_id,
                task_id=source.task_id,
                session_id=None,
                parent_run_id=source.id,
                created_by=None,
                created_by_service_account_id=principal.service_account_id,
                status="created",
                version=1,
                event_sequence=0,
                queue_class=target_queue,
                priority=target_priority,
                idempotency_key=stored_key,
                request_hash=digest,
                input=source.input if input_override is None else input_override,
                api_metadata=metadata,
                product_revision=source.product_revision,
                upstream_revision=source.upstream_revision,
                schema_revision=source.schema_revision,
                adapter_contract_version=source.adapter_contract_version,
                fence_token=0,
            )
            db.add(run)
            db.flush()
            reservation = QuotaReservationRecord(
                tenant_id=source.tenant_id,
                space_id=source.space_id,
                project_id=source.project_id,
                quota_id=quota.id,
                run_id=run.id,
                units=quota_units,
                status="reserved",
                version=1,
            )
            db.add(reservation)
            db.flush()
            quota.reserved_units += quota_units
            quota.version += 1
            self._append_event(
                db,
                run,
                event_type="run.created",
                payload={
                    "status": "created",
                    "retry_of_run_id": str(source.id),
                    "quota_reservation_id": str(reservation.id),
                    "quota_resource": clean_resource,
                    "quota_units": quota_units,
                },
                trace_id=clean_trace,
            )
            run.status = "queued"
            run.version += 1
            self._append_event(
                db,
                run,
                event_type="run.queued",
                payload={
                    "status": "queued",
                    "queue_class": target_queue,
                    "priority": target_priority,
                },
                trace_id=clean_trace,
            )
            return self._run_view(run)

    def list_run_events(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        run_id: UUID,
        cursor: str | None,
        limit: int,
        after_sequence: int | None = None,
    ) -> PublicApiPage:
        if not 1 <= limit <= 500:
            raise PublicApiError("page_limit_invalid", "limit must be between 1 and 500")
        if after_sequence is not None and after_sequence < 0:
            raise PublicApiError("after_sequence_invalid", "after_sequence is invalid")
        resolved_after_sequence = after_sequence or 0
        after_event_id: UUID | None = None
        scope = f"{principal.tenant_id}:{principal.space_id}:{project_id}:{run_id}"
        filters: dict[str, JsonValue] = {"after_sequence": after_sequence}
        if cursor is not None:
            try:
                state = self._cursors.decode(
                    cursor,
                    resource="run-events",
                    scope=scope,
                    filters=filters,
                    sort=("sequence", "id"),
                )
            except CursorError as error:
                raise PublicApiError("cursor_invalid", "cursor is invalid") from error
            values = cast(dict[str, object], state.position)
            raw_sequence = values.get("sequence")
            if not isinstance(raw_sequence, int) or raw_sequence < 0:
                raise PublicApiError("cursor_invalid", "cursor is invalid")
            resolved_after_sequence = raw_sequence
            after_event_id = self._uuid_value(values, "event_id")
        with self._sessions.begin() as db:
            self._require_machine_permission(
                db, principal, project_id=project_id, permission="run.read_content"
            )
            self._run(db, principal, project_id, run_id)
            query = sa.select(RunEventRecord).where(
                RunEventRecord.run_id == run_id,
                RunEventRecord.tenant_id == principal.tenant_id,
                RunEventRecord.space_id == principal.space_id,
                RunEventRecord.project_id == project_id,
            )
            if after_event_id is None:
                query = query.where(RunEventRecord.sequence > resolved_after_sequence)
            else:
                query = query.where(
                    sa.tuple_(RunEventRecord.sequence, RunEventRecord.id)
                    > sa.tuple_(sa.literal(resolved_after_sequence), sa.literal(after_event_id))
                )
            rows = tuple(
                db.scalars(
                    query.order_by(RunEventRecord.sequence, RunEventRecord.id).limit(limit + 1)
                )
            )
            visible = rows[:limit]
            next_cursor = None
            if len(rows) > limit and visible:
                next_cursor = self._cursors.encode(
                    resource="run-events",
                    scope=scope,
                    filters=filters,
                    sort=("sequence", "id"),
                    position={
                        "sequence": visible[-1].sequence,
                        "event_id": str(visible[-1].id),
                    },
                )
            return PublicApiPage(
                tuple(
                    PublicApiRunEventView(
                        row.id,
                        row.run_id,
                        row.sequence,
                        row.event_type,
                        row.trace_id,
                        row.created_at,
                        cast(dict[str, object], row.payload),
                    )
                    for row in visible
                ),
                next_cursor,
            )

    @staticmethod
    def _bound_project_id(principal: ValidatedApiCredential) -> UUID:
        if principal.space_id is None or principal.project_id is None:
            raise PublicApiError(
                "project_scope_required", "Public execution requires a project-scoped credential"
            )
        return principal.project_id

    def _require_machine_permission(
        self,
        db: Session,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        permission: str,
        checked_at: datetime | None = None,
    ) -> ServiceAccountRecord:
        if principal.space_id is None or principal.project_id is None:
            raise PublicApiError(
                "project_scope_required", "Public execution requires a project-scoped credential"
            )
        if db.get_bind().dialect.name == "postgresql" and not bool(
            db.scalar(sa.text("SELECT current_user = 'saas_public_api'"))
        ):
            raise PublicApiError(
                "public_api_database_role_required",
                "Public API database authority is unavailable",
            )
        apply_rls_context(
            db,
            RlsContext(
                actor_id=principal.service_account_id,
                tenant_id=principal.tenant_id,
                space_id=principal.space_id,
                project_id=project_id,
                api_credential_id=principal.credential_id,
            ),
        )
        credential = db.scalar(
            sa.select(ApiCredentialRecord).where(
                ApiCredentialRecord.id == principal.credential_id,
                ApiCredentialRecord.tenant_id == principal.tenant_id,
                ApiCredentialRecord.service_account_id == principal.service_account_id,
            )
        )
        account = db.scalar(
            sa.select(ServiceAccountRecord).where(
                ServiceAccountRecord.id == principal.service_account_id,
                ServiceAccountRecord.tenant_id == principal.tenant_id,
            )
        )
        current = checked_at or _now()
        valid = bool(
            credential is not None
            and account is not None
            and credential.status == "active"
            and credential.revoked_at is None
            and _aware(credential.expires_at) > current
            and account.status == "active"
            and credential.account_security_version == account.security_version
            and account.security_version == principal.security_version
            and account.space_id == principal.space_id
            and account.project_id == project_id
            and principal.project_id == project_id
        )
        if not valid:
            raise PublicApiError("invalid_api_credential", "API credential is invalid")
        scopes = frozenset(cast(ApiCredentialRecord, credential).permission_scopes)
        definition = PERMISSION_CATALOG.get(permission)
        if (
            definition is None
            or not definition.service_account_allowed
            or permission not in scopes
            or permission not in principal.permission_scopes
        ):
            raise PublicApiError("permission_denied", "API credential permission is denied")
        tenant = db.get(Tenant, principal.tenant_id)
        space = db.get(Space, principal.space_id)
        project = self._project(db, principal, project_id)
        if (
            tenant is None
            or tenant.status not in {"trial", "active"}
            or space is None
            or space.status != "active"
            or project.status != "active"
        ):
            raise PublicApiError("scope_unavailable", "API credential scope is unavailable")
        return cast(ServiceAccountRecord, account)

    @staticmethod
    def _project(
        db: Session,
        principal: ValidatedApiCredential,
        project_id: UUID,
    ) -> ProjectRecord:
        project = db.scalar(
            sa.select(ProjectRecord).where(
                ProjectRecord.id == project_id,
                ProjectRecord.tenant_id == principal.tenant_id,
                ProjectRecord.space_id == principal.space_id,
            )
        )
        if project is None:
            raise PublicApiError("project_not_found", "Project was not found")
        return project

    @staticmethod
    def _run(
        db: Session,
        principal: ValidatedApiCredential,
        project_id: UUID,
        run_id: UUID,
        *,
        lock: bool = False,
    ) -> RunRecord:
        query = sa.select(RunRecord).where(
            RunRecord.id == run_id,
            RunRecord.tenant_id == principal.tenant_id,
            RunRecord.space_id == principal.space_id,
            RunRecord.project_id == project_id,
        )
        if lock:
            query = query.with_for_update()
        run = db.scalar(query)
        if run is None:
            raise PublicApiError("run_not_found", "Run was not found")
        return run

    @staticmethod
    def _project_view(project: ProjectRecord) -> PublicApiProjectView:
        return PublicApiProjectView(
            project.id,
            project.tenant_id,
            project.space_id,
            project.name,
            project.visibility,
            project.status,
            project.authorization_version,
            project.created_at,
            project.updated_at,
        )

    @staticmethod
    def _run_view(run: RunRecord, *, replayed: bool = False) -> PublicApiRunView:
        return PublicApiRunView(
            run.id,
            run.task_id,
            run.session_id,
            run.parent_run_id,
            run.tenant_id,
            run.space_id,
            run.project_id,
            run.status,
            run.version,
            run.event_sequence,
            run.queue_class,
            run.priority,
            cast(dict[str, object], run.api_metadata),
            run.created_by,
            run.created_by_service_account_id,
            run.terminal_at,
            run.created_at,
            run.updated_at,
            replayed,
        )

    def _active_stored_run_key(
        self,
        credential_id: UUID,
        *,
        operation: str,
        idempotency_key: str,
    ) -> str:
        key_id, digest = self._idempotency.active_digest(idempotency_key)
        operation_code = self._operation_code(operation)
        return f"public:{credential_id.hex}:{operation_code}:{key_id}:{digest}"

    def _stored_run_keys(
        self,
        credential_id: UUID,
        *,
        operation: str,
        idempotency_key: str,
    ) -> tuple[str, ...]:
        operation_code = self._operation_code(operation)
        return tuple(
            f"public:{credential_id.hex}:{operation_code}:{key_id}:{digest}"
            for key_id, digest in self._idempotency.candidate_digests(idempotency_key)
        )

    @staticmethod
    def _operation_code(operation: str) -> str:
        codes = {"run.create": "create", "run.retry": "retry"}
        try:
            return codes[operation]
        except KeyError as error:
            raise ValueError("unsupported Run idempotency operation") from error

    @staticmethod
    def _serialize_idempotency(
        db: Session,
        principal: ValidatedApiCredential,
        *,
        operation: str,
        idempotency_key: str,
    ) -> None:
        """Serialize one logical key across replicas before lookup and insertion."""

        if db.get_bind().dialect.name != "postgresql":
            return
        cleaned_operation = _text(operation, "operation", 64)
        cleaned_key = _text(idempotency_key, "idempotency_key", 128)
        lock_fingerprint = _canonical_hash(
            {
                "domain": "omnigent-public-api-idempotency-lock-v1",
                "credential_id": str(principal.credential_id),
                "operation": cleaned_operation,
                "idempotency_key": cleaned_key,
            }
        )
        db.execute(
            sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:idempotency_fingerprint, 0))"),
            {"idempotency_fingerprint": lock_fingerprint},
        )

    def _new_run(
        self,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        task_id: UUID,
        session_id: UUID | None,
        input_payload: dict[str, object],
        metadata: dict[str, object],
        stored_key: str,
        request_hash: str,
        queue_class: str,
        priority: int,
    ) -> RunRecord:
        return RunRecord(
            tenant_id=principal.tenant_id,
            space_id=cast(UUID, principal.space_id),
            project_id=project_id,
            task_id=task_id,
            session_id=session_id,
            parent_run_id=None,
            created_by=None,
            created_by_service_account_id=principal.service_account_id,
            status="created",
            version=1,
            event_sequence=0,
            queue_class=queue_class,
            priority=priority,
            idempotency_key=stored_key,
            request_hash=request_hash,
            input=input_payload,
            api_metadata=metadata,
            product_revision=self._product_revision,
            upstream_revision=self._upstream_revision,
            schema_revision=self._schema_revision,
            adapter_contract_version=self._adapter_contract_version,
            fence_token=0,
        )

    def _reserve_quota(
        self,
        db: Session,
        principal: ValidatedApiCredential,
        *,
        project_id: UUID,
        resource: str,
        units: int,
    ) -> AdmissionQuotaRecord:
        quota = db.scalar(
            sa.select(AdmissionQuotaRecord)
            .where(
                AdmissionQuotaRecord.tenant_id == principal.tenant_id,
                AdmissionQuotaRecord.space_id == principal.space_id,
                AdmissionQuotaRecord.project_id == project_id,
                AdmissionQuotaRecord.resource == resource,
            )
            .with_for_update()
        )
        if quota is None:
            raise PublicApiError("quota_not_configured", "Run quota is not configured")
        if quota.reserved_units + quota.consumed_units + units > quota.limit_units:
            raise PublicApiError("quota_exceeded", "Run quota is exhausted")
        return quota

    @staticmethod
    def _require_replay_match(
        run: RunRecord,
        principal: ValidatedApiCredential,
        project_id: UUID,
        request_hash: str,
    ) -> None:
        if (
            run.request_hash != request_hash
            or run.project_id != project_id
            or run.created_by is not None
            or run.created_by_service_account_id != principal.service_account_id
        ):
            raise PublicApiError(
                "idempotency_conflict", "Idempotency-Key was used with another request"
            )

    @staticmethod
    def _require_version(run: RunRecord, expected_version: int) -> None:
        if expected_version <= 0 or run.version != expected_version:
            raise PublicApiError(
                "precondition_failed",
                "If-Match does not match the current resource version",
                details={"current_etag": f'W/"{run.version}"'},
            )

    @staticmethod
    def _append_event(
        db: Session,
        run: RunRecord,
        *,
        event_type: str,
        payload: dict[str, object],
        trace_id: str,
    ) -> None:
        run.event_sequence += 1
        event = RunEventRecord(
            tenant_id=run.tenant_id,
            space_id=run.space_id,
            project_id=run.project_id,
            run_id=run.id,
            sequence=run.event_sequence,
            event_type=event_type,
            payload=payload,
            trace_id=trace_id,
        )
        db.add(event)
        db.flush()
        outbox_payload: dict[str, object] = {
            "event_id": str(event.id),
            "run_id": str(run.id),
            "tenant_id": str(run.tenant_id),
            "space_id": str(run.space_id),
            "project_id": str(run.project_id),
            "sequence": event.sequence,
            "event_type": event_type,
            "payload": payload,
            "trace_id": trace_id,
        }
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=run.tenant_id,
                aggregate_type="run",
                aggregate_key=str(run.id),
                event_type="run.event.persisted",
                payload=outbox_payload,
                idempotency_key=f"run-event:{run.id}:{event.sequence}",
                request_hash=_canonical_hash(outbox_payload),
            )
        )

    @staticmethod
    def _finalize_reservations(db: Session, run: RunRecord) -> None:
        reservations = tuple(
            db.scalars(
                sa.select(QuotaReservationRecord)
                .where(
                    QuotaReservationRecord.run_id == run.id,
                    QuotaReservationRecord.status == "reserved",
                )
                .with_for_update()
            )
        )
        for reservation in reservations:
            quota = db.scalar(
                sa.select(AdmissionQuotaRecord)
                .where(AdmissionQuotaRecord.id == reservation.quota_id)
                .with_for_update()
            )
            if quota is None or quota.reserved_units < reservation.units:
                raise PublicApiError("quota_invariant_broken", "Run quota is inconsistent")
            quota.reserved_units -= reservation.units
            quota.version += 1
            reservation.status = "released"
            reservation.version += 1
            reservation.finalized_at = run.terminal_at

    @staticmethod
    def _clear_lease(run: RunRecord) -> None:
        run.lease_owner = None
        run.lease_token = None
        run.lease_expires_at = None
        run.heartbeat_at = None

    @staticmethod
    def _run_receipt_payload(view: PublicApiRunView) -> dict[str, object]:
        return {
            "id": str(view.id),
            "task_id": str(view.task_id),
            "session_id": str(view.session_id) if view.session_id else None,
            "parent_run_id": str(view.parent_run_id) if view.parent_run_id else None,
            "tenant_id": str(view.tenant_id),
            "space_id": str(view.space_id),
            "project_id": str(view.project_id),
            "status": view.status,
            "version": view.version,
            "event_sequence": view.event_sequence,
            "queue_class": view.queue_class,
            "priority": view.priority,
            "metadata": view.metadata,
            "created_by_user_id": (
                str(view.created_by_user_id) if view.created_by_user_id is not None else None
            ),
            "created_by_service_account_id": (
                str(view.created_by_service_account_id)
                if view.created_by_service_account_id is not None
                else None
            ),
            "terminal_at": view.terminal_at.isoformat() if view.terminal_at else None,
            "created_at": view.created_at.isoformat(),
            "updated_at": view.updated_at.isoformat(),
        }

    @staticmethod
    def _run_view_from_receipt(receipt: PublicApiMutationReceiptRecord) -> PublicApiRunView:
        payload = receipt.response_json
        return PublicApiRunView(
            UUID(cast(str, payload["id"])),
            UUID(cast(str, payload["task_id"])),
            UUID(cast(str, payload["session_id"])) if payload.get("session_id") else None,
            UUID(cast(str, payload["parent_run_id"])) if payload.get("parent_run_id") else None,
            UUID(cast(str, payload["tenant_id"])),
            UUID(cast(str, payload["space_id"])),
            UUID(cast(str, payload["project_id"])),
            cast(str, payload["status"]),
            cast(int, payload["version"]),
            cast(int, payload["event_sequence"]),
            cast(str, payload["queue_class"]),
            cast(int, payload["priority"]),
            cast(dict[str, object], payload["metadata"]),
            UUID(cast(str, payload["created_by_user_id"]))
            if payload.get("created_by_user_id")
            else None,
            UUID(cast(str, payload["created_by_service_account_id"]))
            if payload.get("created_by_service_account_id")
            else None,
            datetime.fromisoformat(cast(str, payload["terminal_at"]))
            if payload.get("terminal_at")
            else None,
            datetime.fromisoformat(cast(str, payload["created_at"])),
            datetime.fromisoformat(cast(str, payload["updated_at"])),
            True,
        )

    def _load_receipt(
        self,
        db: Session,
        principal: ValidatedApiCredential,
        *,
        operation: str,
        idempotency_key: str,
        request_hash: str,
    ) -> PublicApiMutationReceiptRecord | None:
        candidates = self._idempotency.candidate_digests(idempotency_key)
        receipt = db.scalar(
            sa.select(PublicApiMutationReceiptRecord).where(
                PublicApiMutationReceiptRecord.credential_id == principal.credential_id,
                PublicApiMutationReceiptRecord.operation == operation,
                sa.tuple_(
                    PublicApiMutationReceiptRecord.idempotency_key_id,
                    PublicApiMutationReceiptRecord.idempotency_hmac,
                ).in_(candidates),
            )
        )
        if receipt is not None and receipt.request_hash != request_hash:
            raise PublicApiError(
                "idempotency_conflict", "Idempotency-Key was used with another request"
            )
        return receipt

    @staticmethod
    def _uuid_value(values: dict[str, object], name: str) -> UUID:
        raw = values.get(name)
        if not isinstance(raw, str):
            raise PublicApiError("cursor_invalid", "cursor is invalid")
        try:
            return UUID(raw)
        except ValueError as error:
            raise PublicApiError("cursor_invalid", "cursor is invalid") from error

    @staticmethod
    def _datetime_value(values: dict[str, object], name: str) -> datetime:
        raw = values.get(name)
        if not isinstance(raw, str):
            raise PublicApiError("cursor_invalid", "cursor is invalid")
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as error:
            raise PublicApiError("cursor_invalid", "cursor is invalid") from error
        if parsed.tzinfo is None:
            raise PublicApiError("cursor_invalid", "cursor is invalid")
        return parsed
