"""Atomic server-owned Preview child-Run saga.

The browser chooses only a completed source Run and the fixed static profile.
This authority derives every execution, ChangeSet, quota, command, host, and
revision fact inside one transaction.  A committed source checkout is never
reopened for writing: the child Run later materializes a fresh readonly
Worktree from its immutable checkpoint artifact.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn, cast
from urllib.parse import quote
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import (
    AdmissionQuotaRecord,
    QuotaReservationRecord,
    RunRecord,
)
from saas.control_plane.isolation import PreviewRouteGrant
from saas.control_plane.preview_models import (
    PreviewCommandRecord,
    PreviewExecutionRecord,
    PreviewSessionRecord,
)
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.runner_execution_spec import (
    STATIC_WEB_PREVIEW_PROFILE,
    ManagedRunExecutionSpecError,
    preview_request_identity,
    server_owned_preview_run_input,
    static_web_preview_execution,
)
from saas.control_plane.scheduling_models import RunnerRegistrationRecord
from saas.control_plane.worktree_models import ChangeSetRecord, WorktreeInstanceRecord

_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_DNS_SUFFIX = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_RUNNER_AGENT_LOGIN = re.compile(r"^runner_[0-9a-f]{32}_g[1-9][0-9]*$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite's timezone-naive round trip without weakening UTC policy."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_hash(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class PreviewExecutionControlPlaneError(RuntimeError):
    """Stable, content-blind Preview saga error."""

    def __init__(self, code: str, message: str = "Preview is unavailable") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PreviewExecutionPolicy:
    preview_root_domain: str
    exchange_hmac_key: bytes
    lifetime: timedelta = timedelta(hours=1)
    quota_resource: str = "preview_runs"
    quota_units: int = 1

    def __post_init__(self) -> None:
        domain = self.preview_root_domain.lower().rstrip(".")
        if _DNS_SUFFIX.fullmatch(domain) is None:
            raise ValueError("Preview root domain is invalid")
        if len(self.exchange_hmac_key) < 32:
            raise ValueError("Preview exchange HMAC key is too short")
        if not timedelta(minutes=1) <= self.lifetime <= timedelta(hours=24):
            raise ValueError("Preview lifetime is outside the production policy")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", self.quota_resource):
            raise ValueError("Preview quota resource is invalid")
        if self.quota_units <= 0:
            raise ValueError("Preview quota units must be positive")
        object.__setattr__(self, "preview_root_domain", domain)


@dataclass(frozen=True, slots=True)
class PreviewExecutionState:
    preview_execution_id: UUID
    source_run_id: UUID
    child_run_id: UUID
    status: str
    preview_host: str
    expires_at: datetime
    replayed: bool
    exchange_url: str | None = None


@dataclass(frozen=True, slots=True)
class PreviewRunnerStartClaim:
    command_id: UUID
    claim_token: str
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    preview_execution_id: UUID
    child_run_id: UUID
    change_set_id: UUID
    checkpoint_revision: str
    expires_at: datetime
    capability_token: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class PreviewRunnerStopClaim:
    command_id: UUID | None
    claim_token: str | None
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    preview_execution_id: UUID
    terminal: bool = False
    child_run_id: UUID | None = None
    capability_token: str | None = field(default=None, repr=False, compare=False)


class PreviewExecutionControlPlane:
    """Own one active static Preview child Run per source Run."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        policy: PreviewExecutionPolicy,
        authorizer: ProjectAuthorizer | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._policy = policy
        self._authorizer = authorizer or ProjectAuthorizer(session_factory)

    def request_preview(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        source_run_id: UUID,
        preview_kind: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PreviewExecutionState:
        """Create child Run, quota hold, Preview execution and start command atomically."""

        self._authorizer.require(request, action="preview.open", project_id=project_id)
        try:
            identity = preview_request_identity(
                run_id=source_run_id,
                preview_kind=preview_kind,
                idempotency_key=idempotency_key,
            )
        except ManagedRunExecutionSpecError as error:
            raise PreviewExecutionControlPlaneError("preview_request_invalid") from error
        requested_at = now or _utcnow()
        if requested_at.tzinfo is None:
            raise PreviewExecutionControlPlaneError("preview_time_invalid")
        with self._session_factory.begin() as db:
            self._apply_context(db, request, project_id)
            parent = db.scalar(
                sa.select(RunRecord)
                .where(
                    RunRecord.id == source_run_id,
                    RunRecord.tenant_id == request.tenant_id,
                    RunRecord.space_id == request.space_id,
                    RunRecord.project_id == project_id,
                    RunRecord.created_by == request.actor_id,
                )
                .with_for_update()
            )
            if parent is None or parent.status != "succeeded":
                raise PreviewExecutionControlPlaneError("preview_source_unavailable")
            existing = db.scalar(
                sa.select(PreviewExecutionRecord)
                .where(
                    PreviewExecutionRecord.tenant_id == request.tenant_id,
                    PreviewExecutionRecord.created_by == request.actor_id,
                    PreviewExecutionRecord.idempotency_key_hash == identity.key_hash,
                )
                .with_for_update()
            )
            if existing is not None:
                if (
                    existing.request_hash != identity.request_hash
                    or existing.source_run_id != source_run_id
                    or existing.profile != STATIC_WEB_PREVIEW_PROFILE
                ):
                    raise PreviewExecutionControlPlaneError("preview_idempotency_conflict")
                return self._state(existing, replayed=True)
            active = db.scalar(
                sa.select(PreviewExecutionRecord)
                .where(
                    PreviewExecutionRecord.tenant_id == request.tenant_id,
                    PreviewExecutionRecord.project_id == project_id,
                    PreviewExecutionRecord.source_run_id == source_run_id,
                    PreviewExecutionRecord.profile == STATIC_WEB_PREVIEW_PROFILE,
                    PreviewExecutionRecord.status.in_(
                        ("requested", "queued", "materializing", "starting", "ready", "stopping")
                    ),
                )
                .with_for_update()
            )
            if active is not None:
                raise PreviewExecutionControlPlaneError("preview_already_active")
            worktree_change_sets = tuple(
                db.scalars(
                    sa.select(WorktreeInstanceRecord.change_set_id)
                    .where(
                        WorktreeInstanceRecord.run_id == parent.id,
                        WorktreeInstanceRecord.tenant_id == request.tenant_id,
                        WorktreeInstanceRecord.space_id == request.space_id,
                        WorktreeInstanceRecord.project_id == project_id,
                    )
                    .distinct()
                )
            )
            if len(worktree_change_sets) != 1:
                raise PreviewExecutionControlPlaneError("preview_checkpoint_ambiguous")
            change_set = db.scalar(
                sa.select(ChangeSetRecord)
                .where(ChangeSetRecord.id == worktree_change_sets[0])
                .with_for_update()
            )
            if (
                change_set is None
                or change_set.status not in {"checkpointed", "committed"}
                or change_set.head_revision is None
                or _FULL_SHA.fullmatch(change_set.head_revision) is None
                or change_set.recovery_artifact_ref is None
            ):
                raise PreviewExecutionControlPlaneError("preview_checkpoint_unavailable")
            quota = db.scalar(
                sa.select(AdmissionQuotaRecord)
                .where(
                    AdmissionQuotaRecord.tenant_id == request.tenant_id,
                    AdmissionQuotaRecord.space_id == request.space_id,
                    AdmissionQuotaRecord.project_id == project_id,
                    AdmissionQuotaRecord.resource == self._policy.quota_resource,
                )
                .with_for_update()
            )
            if quota is None:
                raise PreviewExecutionControlPlaneError("preview_quota_unconfigured")
            if (
                quota.reserved_units + quota.consumed_units + self._policy.quota_units
                > quota.limit_units
            ):
                raise PreviewExecutionControlPlaneError("preview_quota_exhausted")

            execution_id = uuid4()
            child_run_id = uuid4()
            command_id = uuid4()
            opaque_key = f"pvr_{secrets.token_hex(24)}"
            preview_host = f"{secrets.token_hex(24)}.{self._policy.preview_root_domain}"
            try:
                child_input = server_owned_preview_run_input(
                    preview_execution_id=execution_id,
                    change_set_id=change_set.id,
                    checkpoint_revision=change_set.head_revision,
                )
            except ManagedRunExecutionSpecError as error:
                raise PreviewExecutionControlPlaneError(
                    "preview_checkpoint_unavailable"
                ) from error
            child = RunRecord(
                id=child_run_id,
                tenant_id=parent.tenant_id,
                space_id=parent.space_id,
                project_id=parent.project_id,
                task_id=parent.task_id,
                session_id=parent.session_id,
                parent_run_id=parent.id,
                created_by=request.actor_id,
                status="created",
                version=1,
                event_sequence=0,
                queue_class="preview",
                priority=0,
                idempotency_key=f"preview:{identity.key_hash}",
                request_hash=_canonical_hash(child_input),
                input=child_input,
                api_metadata={"server_owned_profile": STATIC_WEB_PREVIEW_PROFILE},
                product_revision=parent.product_revision,
                upstream_revision=parent.upstream_revision,
                schema_revision=parent.schema_revision,
                adapter_contract_version=parent.adapter_contract_version,
                fence_token=0,
            )
            db.add(child)
            db.flush()
            reservation_id = uuid4()
            db.add(
                QuotaReservationRecord(
                    id=reservation_id,
                    tenant_id=parent.tenant_id,
                    space_id=parent.space_id,
                    project_id=parent.project_id,
                    quota_id=quota.id,
                    run_id=child.id,
                    units=self._policy.quota_units,
                    status="reserved",
                    version=1,
                )
            )
            quota.reserved_units += self._policy.quota_units
            quota.version += 1
            ExecutionControlPlane._append_event(
                db,
                child,
                event_type="run.created",
                payload={
                    "status": "created",
                    "quota_reservation_id": str(reservation_id),
                    "quota_resource": self._policy.quota_resource,
                    "quota_units": self._policy.quota_units,
                    "parent_run_id": str(parent.id),
                    "preview_execution_id": str(execution_id),
                },
                trace_id=request.trace_id,
            )
            child.status = "queued"
            child.version += 1
            ExecutionControlPlane._append_event(
                db,
                child,
                event_type="run.queued",
                payload={"status": "queued", "queue_class": "preview", "priority": 0},
                trace_id=request.trace_id,
            )
            execution = PreviewExecutionRecord(
                id=execution_id,
                tenant_id=parent.tenant_id,
                space_id=parent.space_id,
                project_id=parent.project_id,
                source_run_id=parent.id,
                child_run_id=child.id,
                change_set_id=change_set.id,
                created_by=request.actor_id,
                profile=STATIC_WEB_PREVIEW_PROFILE,
                idempotency_key_hash=identity.key_hash,
                request_hash=identity.request_hash,
                opaque_preview_key=opaque_key,
                preview_host=preview_host,
                status="queued",
                command_generation=0,
                expires_at=requested_at + self._policy.lifetime,
                version=1,
            )
            db.add(execution)
            db.flush()
            command_hash = _canonical_hash(
                {
                    "command_type": "start",
                    "generation": 1,
                    "preview_execution_id": str(execution.id),
                }
            )
            self._create_command(
                db,
                execution=execution,
                command_id=command_id,
                command_type="start",
                request_hash=command_hash,
                operation_at=requested_at,
            )
            command_payload: dict[str, object] = {
                "command_id": str(command_id),
                "command_type": "start",
                "generation": 1,
                "preview_execution_id": str(execution.id),
            }
            db.add(
                ControlPlaneOutboxEvent(
                    tenant_id=parent.tenant_id,
                    aggregate_type="preview_execution",
                    aggregate_key=str(execution.id),
                    event_type="preview.command.available",
                    payload=command_payload,
                    idempotency_key=f"preview-command:{command_id}",
                    request_hash=_canonical_hash(command_payload),
                )
            )
            db.flush()
            return self._state(execution, replayed=False)

    def get_preview(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        preview_execution_id: UUID,
        now: datetime | None = None,
    ) -> PreviewExecutionState:
        """Read actor-owned status and issue a deterministic one-use URL only when ready."""

        self._authorizer.require(request, action="preview.open", project_id=project_id)
        checked_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_context(db, request, project_id)
            execution = db.scalar(
                sa.select(PreviewExecutionRecord).where(
                    PreviewExecutionRecord.id == preview_execution_id,
                    PreviewExecutionRecord.tenant_id == request.tenant_id,
                    PreviewExecutionRecord.space_id == request.space_id,
                    PreviewExecutionRecord.project_id == project_id,
                    PreviewExecutionRecord.created_by == request.actor_id,
                )
            )
            if execution is None:
                raise PreviewExecutionControlPlaneError("preview_unavailable")
            if execution.status != "ready":
                return self._state(execution, replayed=True)
            raw_token = self._exchange_token(execution.id)
            token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
            row = self._issue_exchange(
                db,
                execution=execution,
                token_hash=token_hash,
                operation_at=checked_at,
            )
            if row is None:
                return self._state(execution, replayed=True)
            fragment_token = quote(raw_token, safe="")
            url = f"https://{execution.preview_host}/__omnigent/bootstrap#token={fragment_token}"
            return self._state(execution, replayed=bool(row["replayed"]), exchange_url=url)

    def stop_preview(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        preview_execution_id: UUID,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PreviewExecutionState:
        """Persist an idempotent stop command and revoke every browser session."""

        self._authorizer.require(request, action="preview.open", project_id=project_id)
        try:
            identity = preview_request_identity(
                run_id=preview_execution_id,
                preview_kind=STATIC_WEB_PREVIEW_PROFILE,
                idempotency_key=idempotency_key,
            )
        except ManagedRunExecutionSpecError as error:
            raise PreviewExecutionControlPlaneError("preview_request_invalid") from error
        operation_at = now or _utcnow()
        command_hash = _canonical_hash(
            {
                "idempotency_key_hash": identity.key_hash,
                "operation": "stop",
                "preview_execution_id": str(preview_execution_id),
            }
        )
        with self._session_factory.begin() as db:
            self._apply_context(db, request, project_id)
            execution = db.scalar(
                sa.select(PreviewExecutionRecord)
                .where(
                    PreviewExecutionRecord.id == preview_execution_id,
                    PreviewExecutionRecord.tenant_id == request.tenant_id,
                    PreviewExecutionRecord.space_id == request.space_id,
                    PreviewExecutionRecord.project_id == project_id,
                    PreviewExecutionRecord.created_by == request.actor_id,
                )
                .with_for_update()
            )
            if execution is None:
                raise PreviewExecutionControlPlaneError("preview_unavailable")
            existing = db.scalar(
                sa.select(PreviewCommandRecord).where(
                    PreviewCommandRecord.preview_execution_id == execution.id,
                    PreviewCommandRecord.command_type == "stop",
                    PreviewCommandRecord.request_hash == command_hash,
                )
            )
            if existing is not None:
                return self._state(execution, replayed=True)
            command_id = uuid4()
            self._create_command(
                db,
                execution=execution,
                command_id=command_id,
                command_type="stop",
                request_hash=command_hash,
                operation_at=operation_at,
            )
            payload: dict[str, object] = {
                "command_id": str(command_id),
                "command_type": "stop",
                "generation": execution.command_generation,
                "preview_execution_id": str(execution.id),
            }
            db.add(
                ControlPlaneOutboxEvent(
                    tenant_id=execution.tenant_id,
                    aggregate_type="preview_execution",
                    aggregate_key=str(execution.id),
                    event_type="preview.command.available",
                    payload=payload,
                    idempotency_key=f"preview-command:{command_id}",
                    request_hash=_canonical_hash(payload),
                )
            )
            db.flush()
            return self._state(execution, replayed=False)

    def _exchange_token(self, execution_id: UUID) -> str:
        digest = hmac.digest(
            self._policy.exchange_hmac_key,
            b"omnigent-preview-exchange-v1\0" + execution_id.bytes,
            "sha256",
        )
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def _apply_context(db: Session, request: RequestContext, project_id: UUID) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
            ),
        )

    @staticmethod
    def _create_command(
        db: Session,
        *,
        execution: PreviewExecutionRecord,
        command_id: UUID,
        command_type: str,
        request_hash: str,
        operation_at: datetime,
    ) -> None:
        if db.get_bind().dialect.name == "postgresql":
            result = (
                db.execute(
                    sa.text(
                        "SELECT * FROM public.saas_preview_create_command_v1("
                        ":execution_id, :command_id, :command_type, :request_hash, :operation_at)"
                    ),
                    {
                        "execution_id": execution.id,
                        "command_id": command_id,
                        "command_type": command_type,
                        "request_hash": request_hash,
                        "operation_at": operation_at,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if result is None or result["command_id"] != command_id:
                raise PreviewExecutionControlPlaneError("preview_command_rejected")
            db.refresh(execution)
            return
        generation = execution.command_generation + 1
        db.add(
            PreviewCommandRecord(
                id=command_id,
                tenant_id=execution.tenant_id,
                space_id=execution.space_id,
                project_id=execution.project_id,
                preview_execution_id=execution.id,
                command_type=command_type,
                generation=generation,
                request_hash=request_hash,
                status="pending",
                attempt_count=0,
                available_at=operation_at,
            )
        )
        execution.command_generation = generation
        if command_type == "stop":
            execution.status = "stopping"
            for browser_session in db.scalars(
                sa.select(PreviewSessionRecord).where(
                    PreviewSessionRecord.preview_execution_id == execution.id,
                    PreviewSessionRecord.status == "active",
                )
            ):
                browser_session.status = "revoked"
                browser_session.revoked_at = operation_at
        execution.version += 1

    @staticmethod
    def _issue_exchange(
        db: Session,
        *,
        execution: PreviewExecutionRecord,
        token_hash: str,
        operation_at: datetime,
    ) -> sa.RowMapping | dict[str, object] | None:
        if db.get_bind().dialect.name == "postgresql":
            return (
                db.execute(
                    sa.text(
                        "SELECT * FROM public.saas_preview_issue_exchange_v1("
                        ":execution_id, :token_hash, :operation_at)"
                    ),
                    {
                        "execution_id": execution.id,
                        "token_hash": token_hash,
                        "operation_at": operation_at,
                    },
                )
                .mappings()
                .one_or_none()
            )
        if (
            execution.exchange_consumed_at is not None
            or _as_utc(execution.expires_at) <= operation_at
            or execution.exchange_token_hash not in {None, token_hash}
        ):
            return None
        replayed = execution.exchange_token_hash is not None
        if not replayed:
            execution.exchange_token_hash = token_hash
            execution.exchange_issued_at = operation_at
            execution.version += 1
        return {"replayed": replayed}

    @staticmethod
    def _state(
        execution: PreviewExecutionRecord,
        *,
        replayed: bool,
        exchange_url: str | None = None,
    ) -> PreviewExecutionState:
        return PreviewExecutionState(
            preview_execution_id=execution.id,
            source_run_id=execution.source_run_id,
            child_run_id=execution.child_run_id,
            status=execution.status,
            preview_host=execution.preview_host,
            expires_at=execution.expires_at,
            replayed=replayed,
            exchange_url=exchange_url,
        )


class PreviewRunnerExecutionAuthority:
    """Runner-only command CAS for one scheduled static Preview child Run."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        bind = session_factory.kw.get("bind")
        self._runner_rpc = bool(
            bind is not None
            and bind.dialect.name == "postgresql"
            and _RUNNER_AGENT_LOGIN.fullmatch(bind.url.username or "")
        )

    def claim_start(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        child_run_id: UUID,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        capability_token: str | None = None,
        preview_execution_id: UUID | None = None,
        now: datetime | None = None,
    ) -> PreviewRunnerStartClaim:
        if self._runner_rpc:
            if capability_token is None or preview_execution_id is None:
                raise PreviewExecutionControlPlaneError("preview_capability_required")
            claim_token = self._deterministic_claim_token(
                capability_token,
                operation="start",
                child_run_id=child_run_id,
                preview_execution_id=preview_execution_id,
            )
            try:
                with self._session_factory.begin() as db:
                    result = cast(
                        dict[str, Any],
                        db.scalar(
                            sa.text(
                                "SELECT public.saas_runner_claim_preview_start_v1("
                                ":capability_hash, :runner_id, :child_run_id, "
                                ":preview_execution_id, :connection_generation, "
                                ":run_fence_token, :claim_token_hash)"
                            ),
                            {
                                "capability_hash": hashlib.sha256(
                                    capability_token.encode("ascii")
                                ).hexdigest(),
                                "runner_id": runner_id,
                                "child_run_id": child_run_id,
                                "preview_execution_id": preview_execution_id,
                                "connection_generation": connection_generation,
                                "run_fence_token": run_fence_token,
                                "claim_token_hash": hashlib.sha256(
                                    claim_token.encode("ascii")
                                ).hexdigest(),
                            },
                        ),
                    )
            except sa.exc.DBAPIError as exc:
                self._raise_runner_rpc_error(exc)
            return PreviewRunnerStartClaim(
                command_id=UUID(str(result["command_id"])),
                claim_token=claim_token,
                tenant_id=UUID(str(result["tenant_id"])),
                space_id=UUID(str(result["space_id"])),
                project_id=UUID(str(result["project_id"])),
                preview_execution_id=UUID(str(result["preview_execution_id"])),
                child_run_id=UUID(str(result["child_run_id"])),
                change_set_id=UUID(str(result["change_set_id"])),
                checkpoint_revision=str(result["checkpoint_revision"]),
                expires_at=self._json_datetime(result["expires_at"]),
                capability_token=capability_token,
            )
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, tenant_id, space_id, project_id)
            run, execution, runner = self._locked_runtime(
                db,
                child_run_id=child_run_id,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                operation_at=operation_at,
            )
            command = db.scalar(
                sa.select(PreviewCommandRecord)
                .where(
                    PreviewCommandRecord.preview_execution_id == execution.id,
                    PreviewCommandRecord.command_type == "start",
                )
                .order_by(PreviewCommandRecord.generation.desc())
                .with_for_update()
            )
            if command is None or command.generation != 1:
                raise PreviewExecutionControlPlaneError("preview_start_command_missing")
            stale_claim = command.status in {"claimed", "succeeded"} and (
                execution.run_fence_token != run_fence_token
                or command.runner_id != runner_id
                or command.runner_connection_generation != connection_generation
                or command.run_fence_token != run_fence_token
            )
            if command.status not in {"pending", "claimed", "succeeded"} or (
                command.status in {"claimed", "succeeded"} and not stale_claim
            ):
                raise PreviewExecutionControlPlaneError("preview_start_command_stale")
            if execution.status not in {"queued", "materializing", "starting", "ready"}:
                raise PreviewExecutionControlPlaneError("preview_execution_stale")
            try:
                spec = static_web_preview_execution(run.input)
            except ManagedRunExecutionSpecError as error:
                raise PreviewExecutionControlPlaneError("preview_execution_stale") from error
            checkpoint_revision = spec.checkpoint_revision
            if (
                spec.preview_execution_id != execution.id
                or spec.change_set_id != execution.change_set_id
                or checkpoint_revision is None
                or _as_utc(execution.expires_at) <= operation_at
            ):
                raise PreviewExecutionControlPlaneError("preview_execution_stale")
            claim_token = secrets.token_urlsafe(32)
            command.status = "claimed"
            command.claim_token_hash = hashlib.sha256(claim_token.encode("ascii")).hexdigest()
            command.claimed_by_gateway = "runner-control"
            command.runner_id = runner.id
            command.placement_id = runner.placement_id
            command.runner_connection_generation = connection_generation
            command.run_fence_token = run_fence_token
            command.claimed_at = operation_at
            command.completed_at = None
            command.failure_code = None
            command.attempt_count += 1
            execution.status = "materializing"
            execution.runner_id = runner.id
            execution.placement_id = runner.placement_id
            execution.runner_connection_generation = connection_generation
            execution.run_fence_token = run_fence_token
            execution.worktree_id = None
            execution.worktree_lease_generation = None
            execution.ready_at = None
            execution.version += 1
            self._revoke_sessions(db, execution.id, operation_at)
            return PreviewRunnerStartClaim(
                command_id=command.id,
                claim_token=claim_token,
                tenant_id=execution.tenant_id,
                space_id=execution.space_id,
                project_id=execution.project_id,
                preview_execution_id=execution.id,
                child_run_id=run.id,
                change_set_id=execution.change_set_id,
                checkpoint_revision=checkpoint_revision,
                expires_at=_as_utc(execution.expires_at),
            )

    def mark_starting(
        self,
        claim: PreviewRunnerStartClaim,
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        now: datetime | None = None,
    ) -> None:
        if self._runner_rpc:
            self._transition_postgresql_runner(
                operation="mark_starting",
                claim=claim,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
            )
            return
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, claim.tenant_id, claim.space_id, claim.project_id)
            command, execution = self._locked_claim(
                db,
                claim.command_id,
                claim.claim_token,
                runner_id,
                connection_generation,
                run_fence_token,
            )
            if (
                execution.status != "materializing"
                or _as_utc(execution.expires_at) <= operation_at
            ):
                raise PreviewExecutionControlPlaneError("preview_execution_stale")
            execution.status = "starting"
            execution.version += 1
            command.updated_at = operation_at

    def mark_ready(
        self,
        claim: PreviewRunnerStartClaim,
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        worktree_id: UUID,
        worktree_lease_generation: int,
        now: datetime | None = None,
    ) -> PreviewRouteGrant:
        if self._runner_rpc:
            result = self._transition_postgresql_runner(
                operation="mark_ready",
                claim=claim,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                worktree_id=worktree_id,
                worktree_lease_generation=worktree_lease_generation,
            )
            return self._postgresql_route_grant(
                result,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                worktree_id=worktree_id,
                worktree_lease_generation=worktree_lease_generation,
            )
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, claim.tenant_id, claim.space_id, claim.project_id)
            command, execution = self._locked_claim(
                db,
                claim.command_id,
                claim.claim_token,
                runner_id,
                connection_generation,
                run_fence_token,
            )
            worktree = self._locked_ready_worktree(
                db,
                execution=execution,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                worktree_id=worktree_id,
                worktree_lease_generation=worktree_lease_generation,
                operation_at=operation_at,
            )
            execution.status = "ready"
            execution.worktree_id = worktree.id
            execution.worktree_lease_generation = worktree.lease_generation
            execution.ready_at = operation_at
            execution.version += 1
            command.status = "succeeded"
            command.completed_at = operation_at
            command.updated_at = operation_at
            return self._route_grant(
                execution,
                worktree,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
            )

    def prepare_route(
        self,
        claim: PreviewRunnerStartClaim,
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        worktree_id: UUID,
        worktree_lease_generation: int,
        now: datetime | None = None,
    ) -> PreviewRouteGrant:
        """Validate an unpublished route before starting the local process.

        The durable execution remains ``starting`` until the supervisor has
        pinned and health-checked its socket and :meth:`mark_ready` repeats the
        same database fence under lock.
        """

        if self._runner_rpc:
            result = self._transition_postgresql_runner(
                operation="prepare_route",
                claim=claim,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                worktree_id=worktree_id,
                worktree_lease_generation=worktree_lease_generation,
            )
            return self._postgresql_route_grant(
                result,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                worktree_id=worktree_id,
                worktree_lease_generation=worktree_lease_generation,
            )
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, claim.tenant_id, claim.space_id, claim.project_id)
            _command, execution = self._locked_claim(
                db,
                claim.command_id,
                claim.claim_token,
                runner_id,
                connection_generation,
                run_fence_token,
            )
            worktree = self._locked_ready_worktree(
                db,
                execution=execution,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                worktree_id=worktree_id,
                worktree_lease_generation=worktree_lease_generation,
                operation_at=operation_at,
            )
            return self._route_grant(
                execution,
                worktree,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
            )

    @staticmethod
    def _route_grant(
        execution: PreviewExecutionRecord,
        worktree: WorktreeInstanceRecord,
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
    ) -> PreviewRouteGrant:
        return PreviewRouteGrant(
            preview_id=execution.id,
            tenant_id=execution.tenant_id,
            space_id=execution.space_id,
            project_id=execution.project_id,
            runner_id=runner_id,
            runner_connection_generation=connection_generation,
            run_id=execution.child_run_id,
            run_fence_token=run_fence_token,
            worktree_id=worktree.id,
            worktree_lease_generation=worktree.lease_generation,
            opaque_preview_key=execution.opaque_preview_key,
            preview_token_hash="0" * 64,
            upstream_request_headers={},
            response_headers={
                "Content-Security-Policy": (
                    "sandbox allow-scripts allow-forms allow-modals allow-same-origin; "
                    "default-src 'self'; connect-src 'none'; frame-src 'none'; "
                    "worker-src 'none'; object-src 'none'; base-uri 'none'; "
                    "frame-ancestors 'none'"
                )
            },
            expires_at=_as_utc(execution.expires_at),
            preview_host=execution.preview_host,
        )

    @staticmethod
    def _locked_ready_worktree(
        db: Session,
        *,
        execution: PreviewExecutionRecord,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        worktree_id: UUID,
        worktree_lease_generation: int,
        operation_at: datetime,
    ) -> WorktreeInstanceRecord:
        worktree = db.scalar(
            sa.select(WorktreeInstanceRecord)
            .where(WorktreeInstanceRecord.id == worktree_id)
            .with_for_update()
        )
        if (
            execution.status != "starting"
            or _as_utc(execution.expires_at) <= operation_at
            or worktree is None
            or worktree.run_id != execution.child_run_id
            or worktree.change_set_id != execution.change_set_id
            or worktree.runner_id != runner_id
            or worktree.runner_connection_generation != connection_generation
            or worktree.run_fence_token != run_fence_token
            or worktree.lease_generation != worktree_lease_generation
            or worktree.access_mode != "readonly"
            or worktree.status != "ready"
            or worktree.lease_expires_at is None
            or _as_utc(worktree.lease_expires_at) <= operation_at
        ):
            raise PreviewExecutionControlPlaneError("preview_ready_fence_stale")
        return worktree

    def claim_stop(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        preview_execution_id: UUID,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        child_run_id: UUID | None = None,
        capability_token: str | None = None,
        now: datetime | None = None,
    ) -> PreviewRunnerStopClaim | None:
        if self._runner_rpc:
            if capability_token is None or child_run_id is None:
                raise PreviewExecutionControlPlaneError("preview_capability_required")
            claim_token = self._deterministic_claim_token(
                capability_token,
                operation="stop",
                child_run_id=child_run_id,
                preview_execution_id=preview_execution_id,
            )
            try:
                with self._session_factory.begin() as db:
                    result = cast(
                        dict[str, Any],
                        db.scalar(
                            sa.text(
                                "SELECT public.saas_runner_claim_preview_stop_v1("
                                ":capability_hash, :runner_id, :child_run_id, "
                                ":preview_execution_id, :connection_generation, "
                                ":run_fence_token, :claim_token_hash)"
                            ),
                            {
                                "capability_hash": hashlib.sha256(
                                    capability_token.encode("ascii")
                                ).hexdigest(),
                                "runner_id": runner_id,
                                "child_run_id": child_run_id,
                                "preview_execution_id": preview_execution_id,
                                "connection_generation": connection_generation,
                                "run_fence_token": run_fence_token,
                                "claim_token_hash": hashlib.sha256(
                                    claim_token.encode("ascii")
                                ).hexdigest(),
                            },
                        ),
                    )
            except sa.exc.DBAPIError as exc:
                self._raise_runner_rpc_error(exc)
            if result["command_id"] is None and not bool(result["terminal"]):
                return None
            return PreviewRunnerStopClaim(
                command_id=(
                    None if result["command_id"] is None else UUID(str(result["command_id"]))
                ),
                claim_token=None if bool(result["terminal"]) else claim_token,
                tenant_id=UUID(str(result["tenant_id"])),
                space_id=UUID(str(result["space_id"])),
                project_id=UUID(str(result["project_id"])),
                preview_execution_id=UUID(str(result["preview_execution_id"])),
                terminal=bool(result["terminal"]),
                child_run_id=child_run_id,
                capability_token=capability_token,
            )
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, tenant_id, space_id, project_id)
            execution = db.scalar(
                sa.select(PreviewExecutionRecord)
                .where(PreviewExecutionRecord.id == preview_execution_id)
                .with_for_update()
            )
            if execution is None:
                raise PreviewExecutionControlPlaneError("preview_execution_stale")
            if execution.status in {"stopped", "failed", "revoked"}:
                return PreviewRunnerStopClaim(
                    None,
                    None,
                    execution.tenant_id,
                    execution.space_id,
                    execution.project_id,
                    execution.id,
                    terminal=True,
                )
            if (
                execution.runner_id != runner_id
                or execution.runner_connection_generation != connection_generation
                or execution.run_fence_token != run_fence_token
            ):
                raise PreviewExecutionControlPlaneError("preview_execution_stale")
            command = db.scalar(
                sa.select(PreviewCommandRecord)
                .where(
                    PreviewCommandRecord.preview_execution_id == execution.id,
                    PreviewCommandRecord.command_type == "stop",
                )
                .order_by(PreviewCommandRecord.generation.desc())
                .with_for_update()
            )
            if command is None and _as_utc(execution.expires_at) <= operation_at:
                command = PreviewCommandRecord(
                    id=uuid4(),
                    tenant_id=execution.tenant_id,
                    space_id=execution.space_id,
                    project_id=execution.project_id,
                    preview_execution_id=execution.id,
                    command_type="stop",
                    generation=execution.command_generation + 1,
                    request_hash=_canonical_hash(
                        {
                            "operation": "expire",
                            "preview_execution_id": str(execution.id),
                        }
                    ),
                    status="pending",
                    attempt_count=0,
                    available_at=operation_at,
                )
                db.add(command)
                execution.command_generation = command.generation
            stale_claim = (
                command is not None
                and command.status == "claimed"
                and (
                    command.runner_id != runner_id
                    or command.runner_connection_generation != connection_generation
                    or command.run_fence_token != run_fence_token
                )
            )
            if (
                command is None
                or command.status not in {"pending", "claimed"}
                or (command.status == "claimed" and not stale_claim)
            ):
                return None
            claim_token = secrets.token_urlsafe(32)
            command.status = "claimed"
            command.claim_token_hash = hashlib.sha256(claim_token.encode("ascii")).hexdigest()
            command.claimed_by_gateway = "runner-control"
            command.runner_id = runner_id
            command.placement_id = execution.placement_id
            command.runner_connection_generation = connection_generation
            command.run_fence_token = run_fence_token
            command.claimed_at = operation_at
            command.attempt_count += 1
            execution.status = "stopping"
            execution.version += 1
            self._revoke_sessions(db, execution.id, operation_at)
            return PreviewRunnerStopClaim(
                command.id,
                claim_token,
                execution.tenant_id,
                execution.space_id,
                execution.project_id,
                execution.id,
            )

    def complete_stop(
        self,
        claim: PreviewRunnerStopClaim,
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        success: bool,
        now: datetime | None = None,
    ) -> None:
        if claim.command_id is None or claim.claim_token is None or claim.terminal:
            return
        if self._runner_rpc:
            self._transition_postgresql_runner(
                operation="complete_stop",
                claim=claim,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                success=success,
            )
            return
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, claim.tenant_id, claim.space_id, claim.project_id)
            command, execution = self._locked_claim(
                db,
                claim.command_id,
                claim.claim_token,
                runner_id,
                connection_generation,
                run_fence_token,
            )
            if command.command_type != "stop" or execution.status != "stopping":
                raise PreviewExecutionControlPlaneError("preview_stop_command_stale")
            command.status = "succeeded" if success else "failed"
            command.failure_code = None if success else "preview_stop_failed"
            command.completed_at = operation_at
            command.updated_at = operation_at
            execution.status = "stopped" if success else "failed"
            execution.failure_code = None if success else "preview_stop_failed"
            execution.terminal_at = operation_at
            execution.version += 1
            self._revoke_sessions(db, execution.id, operation_at)

    def fail_start(
        self,
        claim: PreviewRunnerStartClaim,
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        failure_code: str,
        now: datetime | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", failure_code):
            failure_code = "preview_start_failed"
        if self._runner_rpc:
            self._transition_postgresql_runner(
                operation="fail_start",
                claim=claim,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                failure_code=failure_code,
            )
            return
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, claim.tenant_id, claim.space_id, claim.project_id)
            command, execution = self._locked_claim(
                db,
                claim.command_id,
                claim.claim_token,
                runner_id,
                connection_generation,
                run_fence_token,
            )
            command.status = "failed"
            command.failure_code = failure_code
            command.completed_at = operation_at
            command.updated_at = operation_at
            execution.status = "failed"
            execution.failure_code = failure_code
            execution.terminal_at = operation_at
            execution.version += 1
            self._revoke_sessions(db, execution.id, operation_at)

    def abort_runtime(
        self,
        claim: PreviewRunnerStartClaim,
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        cancelled: bool,
        now: datetime | None = None,
    ) -> None:
        """Terminalize one exact current Preview incarnation after local cleanup."""

        if self._runner_rpc:
            self._transition_postgresql_runner(
                operation="abort_runtime",
                claim=claim,
                runner_id=runner_id,
                connection_generation=connection_generation,
                run_fence_token=run_fence_token,
                cancelled=cancelled,
            )
            return
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            self._apply_runner_context(db, claim.tenant_id, claim.space_id, claim.project_id)
            execution = db.scalar(
                sa.select(PreviewExecutionRecord)
                .where(PreviewExecutionRecord.id == claim.preview_execution_id)
                .with_for_update()
            )
            if execution is None:
                raise PreviewExecutionControlPlaneError("preview_execution_stale")
            if execution.status in {"stopped", "failed", "revoked"}:
                return
            if (
                execution.runner_id != runner_id
                or execution.runner_connection_generation != connection_generation
                or execution.run_fence_token != run_fence_token
            ):
                raise PreviewExecutionControlPlaneError("preview_execution_stale")
            command = db.scalar(
                sa.select(PreviewCommandRecord)
                .where(PreviewCommandRecord.id == claim.command_id)
                .with_for_update()
            )
            if command is not None and command.status == "claimed":
                command.status = "cancelled" if cancelled else "failed"
                command.failure_code = None if cancelled else "preview_runtime_failed"
                command.completed_at = operation_at
                command.updated_at = operation_at
            execution.status = "revoked" if cancelled else "failed"
            execution.failure_code = None if cancelled else "preview_runtime_failed"
            execution.terminal_at = operation_at
            execution.version += 1
            self._revoke_sessions(db, execution.id, operation_at)

    def _transition_postgresql_runner(
        self,
        *,
        operation: str,
        claim: PreviewRunnerStartClaim | PreviewRunnerStopClaim,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        worktree_id: UUID | None = None,
        worktree_lease_generation: int | None = None,
        success: bool | None = None,
        cancelled: bool | None = None,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        child_run_id = claim.child_run_id
        capability_token = claim.capability_token
        if (
            claim.command_id is None
            or claim.claim_token is None
            or child_run_id is None
            or capability_token is None
        ):
            raise PreviewExecutionControlPlaneError("preview_capability_required")
        try:
            with self._session_factory.begin() as db:
                result = cast(
                    dict[str, Any],
                    db.scalar(
                        sa.text(
                            "SELECT public.saas_runner_transition_preview_v1("
                            ":operation, :capability_hash, :runner_id, :child_run_id, "
                            ":preview_execution_id, :connection_generation, "
                            ":run_fence_token, :command_id, :claim_token_hash, "
                            ":worktree_id, :worktree_generation, :success, :cancelled, "
                            ":failure_code)"
                        ),
                        {
                            "operation": operation,
                            "capability_hash": hashlib.sha256(
                                capability_token.encode("ascii")
                            ).hexdigest(),
                            "runner_id": runner_id,
                            "child_run_id": child_run_id,
                            "preview_execution_id": claim.preview_execution_id,
                            "connection_generation": connection_generation,
                            "run_fence_token": run_fence_token,
                            "command_id": claim.command_id,
                            "claim_token_hash": hashlib.sha256(
                                claim.claim_token.encode("ascii")
                            ).hexdigest(),
                            "worktree_id": worktree_id,
                            "worktree_generation": worktree_lease_generation,
                            "success": success,
                            "cancelled": cancelled,
                            "failure_code": failure_code,
                        },
                    ),
                )
        except sa.exc.DBAPIError as exc:
            self._raise_runner_rpc_error(exc)
        return result

    @staticmethod
    def _deterministic_claim_token(
        capability_token: str,
        *,
        operation: str,
        child_run_id: UUID,
        preview_execution_id: UUID,
    ) -> str:
        identity = (f"{operation}|{child_run_id}|{preview_execution_id}").encode("ascii")
        return (
            "pct_"
            + hmac.new(
                capability_token.encode("ascii"),
                b"omnigent-preview-command-claim-v1\x00" + identity,
                hashlib.sha256,
            ).hexdigest()
        )

    @staticmethod
    def _json_datetime(value: object) -> datetime:
        if isinstance(value, datetime):
            return _as_utc(value)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return _as_utc(parsed)

    @classmethod
    def _postgresql_route_grant(
        cls,
        result: dict[str, Any],
        *,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        worktree_id: UUID,
        worktree_lease_generation: int,
    ) -> PreviewRouteGrant:
        if (
            result.get("worktree_id") != str(worktree_id)
            or int(result.get("worktree_lease_generation") or 0) != worktree_lease_generation
        ):
            raise PreviewExecutionControlPlaneError("preview_ready_fence_stale")
        return PreviewRouteGrant(
            preview_id=UUID(str(result["preview_execution_id"])),
            tenant_id=UUID(str(result["tenant_id"])),
            space_id=UUID(str(result["space_id"])),
            project_id=UUID(str(result["project_id"])),
            runner_id=runner_id,
            runner_connection_generation=connection_generation,
            run_id=UUID(str(result["child_run_id"])),
            run_fence_token=run_fence_token,
            worktree_id=worktree_id,
            worktree_lease_generation=worktree_lease_generation,
            opaque_preview_key=str(result["opaque_preview_key"]),
            preview_token_hash="0" * 64,
            upstream_request_headers={},
            response_headers={
                "Content-Security-Policy": (
                    "sandbox allow-scripts allow-forms allow-modals allow-same-origin; "
                    "default-src 'self'; connect-src 'none'; frame-src 'none'; "
                    "worker-src 'none'; object-src 'none'; base-uri 'none'; "
                    "frame-ancestors 'none'"
                )
            },
            expires_at=cls._json_datetime(result["expires_at"]),
            preview_host=str(result["preview_host"]),
        )

    @staticmethod
    def _raise_runner_rpc_error(exc: sa.exc.DBAPIError) -> NoReturn:
        sqlstate = getattr(exc.orig, "sqlstate", None)
        if sqlstate == "22023":
            code = "preview_request_invalid"
        elif sqlstate == "55000":
            code = "preview_idempotency_conflict"
        else:
            code = "preview_execution_stale"
        raise PreviewExecutionControlPlaneError(code) from exc

    @staticmethod
    def _apply_runner_context(
        db: Session, tenant_id: UUID, space_id: UUID, project_id: UUID
    ) -> None:
        apply_rls_context(
            db,
            RlsContext(
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
            ),
        )

    @staticmethod
    def _locked_runtime(
        db: Session,
        *,
        child_run_id: UUID,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
        operation_at: datetime,
    ) -> tuple[RunRecord, PreviewExecutionRecord, RunnerRegistrationRecord]:
        runner = db.scalar(
            sa.select(RunnerRegistrationRecord)
            .where(RunnerRegistrationRecord.id == runner_id)
            .with_for_update()
        )
        run = db.scalar(sa.select(RunRecord).where(RunRecord.id == child_run_id).with_for_update())
        execution = db.scalar(
            sa.select(PreviewExecutionRecord)
            .where(PreviewExecutionRecord.child_run_id == child_run_id)
            .with_for_update()
        )
        run_expiry = None if run is None else run.lease_expires_at
        if run_expiry is not None and run_expiry.tzinfo is None:
            run_expiry = run_expiry.replace(tzinfo=timezone.utc)
        if (
            runner is None
            or runner.status not in {"online", "draining"}
            or runner.connection_generation != connection_generation
            or run is None
            or run.status != "running"
            or run.lease_owner != str(runner_id)
            or run.fence_token != run_fence_token
            or run_expiry is None
            or run_expiry <= operation_at
            or execution is None
            or (
                execution.runner_id not in {None, runner_id}
                and execution.run_fence_token == run_fence_token
            )
        ):
            raise PreviewExecutionControlPlaneError("preview_runner_fence_stale")
        return run, execution, runner

    @staticmethod
    def _locked_claim(
        db: Session,
        command_id: UUID,
        claim_token: str,
        runner_id: UUID,
        connection_generation: int,
        run_fence_token: int,
    ) -> tuple[PreviewCommandRecord, PreviewExecutionRecord]:
        token_hash = hashlib.sha256(claim_token.encode("ascii")).hexdigest()
        command = db.scalar(
            sa.select(PreviewCommandRecord)
            .where(PreviewCommandRecord.id == command_id)
            .with_for_update()
        )
        execution = (
            None
            if command is None
            else db.scalar(
                sa.select(PreviewExecutionRecord)
                .where(PreviewExecutionRecord.id == command.preview_execution_id)
                .with_for_update()
            )
        )
        if (
            command is None
            or execution is None
            or command.status != "claimed"
            or command.claim_token_hash is None
            or not hmac.compare_digest(command.claim_token_hash, token_hash)
            or command.runner_id != runner_id
            or command.runner_connection_generation != connection_generation
            or command.run_fence_token != run_fence_token
            or execution.runner_id != runner_id
            or execution.runner_connection_generation != connection_generation
            or execution.run_fence_token != run_fence_token
        ):
            raise PreviewExecutionControlPlaneError("preview_command_claim_stale")
        return command, execution

    @staticmethod
    def _revoke_sessions(db: Session, execution_id: UUID, operation_at: datetime) -> None:
        for browser_session in db.scalars(
            sa.select(PreviewSessionRecord).where(
                PreviewSessionRecord.preview_execution_id == execution_id,
                PreviewSessionRecord.status == "active",
            )
        ):
            browser_session.status = "revoked"
            browser_session.revoked_at = operation_at
            browser_session.updated_at = operation_at


__all__ = [
    "PreviewExecutionControlPlane",
    "PreviewExecutionControlPlaneError",
    "PreviewExecutionPolicy",
    "PreviewExecutionState",
    "PreviewRunnerExecutionAuthority",
    "PreviewRunnerStartClaim",
    "PreviewRunnerStopClaim",
]
