"""Map authenticated Runtime messages to durable SaaS execution intent."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.db_models import current_workspace_id
from omnigent.db.query_context import query_name_scope
from omnigent.entities import Conversation
from omnigent.server.schemas import SessionEventInput
from saas.compatibility import RequestContext, RuntimeContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import (
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.execution import ExecutionControlPlane, ExecutionRevisionSet
from saas.control_plane.execution_models import (
    TERMINAL_RUN_STATUSES,
    ExecutionSessionRecord,
    RunRecord,
)
from saas.control_plane.interactive_launch import interactive_conversation_launch
from saas.control_plane.interactive_run_route import (
    INTERACTIVE_EXECUTION_KIND,
    INTERACTIVE_QUEUE_CLASS,
    interactive_message_intent,
    interactive_session_identity,
)
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.run_customer_pricing import freeze_sqlite_customer_pricing

MANAGED_EXECUTION_SNAPSHOT_KEY = "managed_execution"


class InteractiveExecutionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RuntimeSessionRunAdmission:
    """Admit input only; a queued Run is not a model or Runner capability."""

    def __init__(
        self, sessions: sessionmaker[Session], *, revisions: ExecutionRevisionSet
    ) -> None:
        self._sessions = sessions
        self._execution = ExecutionControlPlane(sessions)
        self._authorization = ProjectAuthorizer(sessions)
        self._revisions = revisions

    def prepare_selection(
        self,
        runtime: RuntimeContext,
        *,
        runtime_project_id: str | None,
        model_id: str,
        configuration_revision: str,
        existing: Conversation | None = None,
    ) -> dict[str, object]:
        from saas.control_plane.tenant_model_catalog import TenantModelCatalog

        self.require_selection_project(runtime, runtime_project_id)
        if existing is not None:
            marker = (existing.inference_snapshot or {}).get(MANAGED_EXECUTION_SNAPSHOT_KEY)
            if (
                not isinstance(marker, dict)
                or existing.project_id != runtime_project_id
                or existing.model_override != model_id
                or configuration_revision
                != (
                    f"managed-model:{marker.get('wire_api')}:{marker.get('generation')}:"
                    f"{marker.get('snapshot_sha256')}"
                )
            ):
                raise InteractiveExecutionError("interactive_create_conflict")
            self.publication_configuration(runtime, marker)
            return marker
        return TenantModelCatalog(self._sessions.kw["bind"]).resolve_selection(
            runtime,
            model_id=model_id,
            configuration_revision=configuration_revision,
        )

    def require_selection_project(
        self, runtime: RuntimeContext, runtime_project_id: str | None
    ) -> None:
        """Read current project authority without creating or reserving execution intent."""
        if current_workspace_id() != runtime.physical_workspace_id:
            raise InteractiveExecutionError("interactive_workspace_mismatch")
        request, project_id = self._project(runtime, runtime_project_id)
        self._authorization.require(request, action="run.create", project_id=project_id)

    def dispatch(
        self,
        runtime: RuntimeContext,
        conversation: Conversation,
        event: SessionEventInput,
        *,
        created_by: str | None,
    ) -> dict[str, bool | str]:
        if current_workspace_id() != runtime.physical_workspace_id:
            raise InteractiveExecutionError("interactive_workspace_mismatch")
        if created_by != runtime.runtime_user_key or event.created_by is not None:
            raise InteractiveExecutionError("interactive_actor_required")
        if event.tools is not None:
            raise InteractiveExecutionError("interactive_client_tools_not_supported")
        if conversation.kind != "default" or conversation.parent_conversation_id is not None:
            raise InteractiveExecutionError("interactive_child_run_not_supported")
        if event.type not in {"message", "interrupt", "retry_session"}:
            raise InteractiveExecutionError("interactive_event_not_supported")
        request, project_id = self._project(runtime, conversation.project_id)
        if event.type != "message":
            session_id = self._session(runtime, request, conversation, project_id, create=False)
            return self._control(request, project_id, session_id, event.type)
        marker = (conversation.inference_snapshot or {}).get(MANAGED_EXECUTION_SNAPSHOT_KEY)
        if not isinstance(marker, dict) or set(marker) != {
            "schema_version",
            "public_model_id",
            "wire_api",
            "generation",
            "snapshot_sha256",
        }:
            raise InteractiveExecutionError("interactive_model_snapshot_invalid")
        if (
            type(marker.get("schema_version")) is not int
            or marker.get("schema_version") != 1
            or marker.get("public_model_id") != conversation.model_override
        ):
            raise InteractiveExecutionError("interactive_model_snapshot_invalid")
        if (
            event.model_override is not None
            and event.model_override != conversation.model_override
        ):
            raise InteractiveExecutionError("interactive_model_override_denied")
        stable_id, title = interactive_message_intent(event.model_dump(mode="json"))
        launch = interactive_conversation_launch(conversation)
        self._authorization.require(request, action="run.create", project_id=project_id)
        self.publication_configuration(runtime, marker)
        session_id = self._session(runtime, request, conversation, project_id, create=True)
        assert session_id is not None
        key = sha256(
            f"{runtime.runtime_partition_id}:{session_id}:{stable_id}".encode()
        ).hexdigest()
        admitted = self._execution.admit_task_run(
            request,
            project_id=project_id,
            session_id=session_id,
            title=title,
            input_payload={
                "execution": {
                    "kind": INTERACTIVE_EXECUTION_KIND,
                    "runtime_partition_id": str(runtime.runtime_partition_id),
                    "runtime_partition_generation": runtime.placement_generation,
                    "runtime_session_id": conversation.id,
                    "runtime_project_id": conversation.project_id,
                    "model_publication": marker,
                    "launch": launch,
                    "event": event.model_dump(mode="json"),
                }
            },
            quota_resource="run",
            quota_units=1,
            idempotency_key=f"interactive-message:{key}",
            revisions=self._revisions,
            queue_class=INTERACTIVE_QUEUE_CLASS,
        )
        return {
            "queued": admitted.status not in TERMINAL_RUN_STATUSES,
            "run_id": str(admitted.run_id),
            "run_status": admitted.status,
        }

    @staticmethod
    def _context(db: Session, runtime: RuntimeContext) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=runtime.actor_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=runtime.project_id,
            ),
        )

    def _project(
        self, runtime: RuntimeContext, runtime_project_id: str | None
    ) -> tuple[RequestContext, UUID]:
        if not runtime_project_id:
            raise InteractiveExecutionError("interactive_project_required")
        with (
            query_name_scope("saas.interactive_execution.resolve_project"),
            self._sessions.begin() as db,
        ):
            self._context(db, runtime)
            binding = db.scalar(
                sa.select(RuntimeResourceBindingRecord).where(
                    RuntimeResourceBindingRecord.runtime_partition_id
                    == runtime.runtime_partition_id,
                    RuntimeResourceBindingRecord.tenant_id == runtime.tenant_id,
                    RuntimeResourceBindingRecord.space_id == runtime.space_id,
                    RuntimeResourceBindingRecord.resource_type == "project",
                    RuntimeResourceBindingRecord.runtime_resource_id == runtime_project_id,
                    RuntimeResourceBindingRecord.status == "active",
                    RuntimeResourceBindingRecord.partition_generation
                    == runtime.placement_generation,
                )
            )
            if (
                binding is None
                or binding.project_id is None
                or binding.project_id != binding.saas_resource_id
                or (runtime.project_id is not None and runtime.project_id != binding.project_id)
            ):
                raise InteractiveExecutionError("interactive_project_not_accessible")
            project_id = binding.project_id
        return RequestContext(
            actor_id=runtime.actor_id,
            tenant_id=runtime.tenant_id,
            space_id=runtime.space_id,
            project_id=project_id,
            user_security_version=runtime.user_security_version,
            tenant_membership_version=runtime.tenant_membership_version,
            space_membership_version=runtime.space_membership_version,
            trace_id=runtime.trace_id,
        ), project_id

    def publication_configuration(
        self, runtime: RuntimeContext, marker: dict[str, object]
    ) -> dict[str, Any]:
        from saas.control_plane.tenant_model_catalog import TenantModelCatalog

        catalog = TenantModelCatalog(self._sessions.kw["bind"])
        return catalog.require_version(runtime, marker)

    def _session(
        self,
        runtime: RuntimeContext,
        request: RequestContext,
        conversation: Conversation,
        project_id: UUID,
        *,
        create: bool,
    ) -> UUID | None:
        # A stable identity is not authority; recheck scope and placement before use.
        session_id = interactive_session_identity(
            runtime.tenant_id,
            runtime.space_id,
            runtime.runtime_partition_id,
            conversation.id,
        )
        with (
            query_name_scope("saas.interactive_execution.bind_session"),
            self._sessions.begin() as db,
        ):
            self._context(db, replace(runtime, project_id=project_id))
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {
                        "key": (
                            f"interactive-session:{runtime.runtime_partition_id}:{conversation.id}"
                        )
                    },
                )
            current = db.execute(
                sa.select(
                    RuntimePartitionRecord, RuntimePlacementRecord, RuntimeIdentityAliasRecord
                )
                .select_from(RuntimePartitionRecord)
                .join(
                    RuntimePlacementRecord,
                    RuntimePlacementRecord.id == RuntimePartitionRecord.placement_id,
                )
                .join(
                    RuntimeIdentityAliasRecord,
                    sa.and_(
                        RuntimeIdentityAliasRecord.runtime_partition_id
                        == RuntimePartitionRecord.id,
                        RuntimeIdentityAliasRecord.user_id == runtime.actor_id,
                    ),
                )
                .where(
                    RuntimePartitionRecord.id == runtime.runtime_partition_id,
                    RuntimePartitionRecord.tenant_id == runtime.tenant_id,
                    RuntimePartitionRecord.space_id == runtime.space_id,
                )
            ).one_or_none()
            if current is None:
                raise InteractiveExecutionError("interactive_partition_stale")
            partition, placement, alias = current
            if (
                partition.status != "active"
                or placement.status != "active"
                or alias.status != "active"
                or partition.placement_id != runtime.placement_id
                or partition.placement_generation != runtime.placement_generation
                or partition.physical_partition_key != str(runtime.physical_workspace_id)
                or partition.source_revision != runtime.source_revision
                or partition.adapter_contract_version != runtime.adapter_contract_version
                or partition.runtime_type != runtime.runtime_type
                or placement.runtime_type != runtime.runtime_type
                or placement.data_region != runtime.data_region
                or placement.official_schema_revision != self._revisions.schema_revision
                or alias.runtime_user_key != runtime.runtime_user_key
            ):
                raise InteractiveExecutionError("interactive_partition_stale")
            session = db.get(ExecutionSessionRecord, session_id)
            if session is not None:
                if (
                    session.tenant_id != runtime.tenant_id
                    or session.space_id != runtime.space_id
                    or session.project_id != project_id
                ):
                    raise InteractiveExecutionError("interactive_session_binding_stale")
                return session.id
            if not create:
                return None
            session = ExecutionSessionRecord(
                id=session_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
                created_by=request.actor_id,
                status="active",
                version=1,
            )
            freeze_sqlite_customer_pricing(db, session)
            db.add(session)
            db.flush()
            if not session.customer_pricing_frozen or session.customer_pricing_snapshot_id is None:
                raise InteractiveExecutionError("interactive_customer_price_unavailable")
            return session_id

    def _control(
        self, request: RequestContext, project_id: UUID, session_id: UUID | None, event_type: str
    ) -> dict[str, bool | str]:
        self._authorization.require(request, action="run.read_content", project_id=project_id)
        if session_id is None:
            return {"queued": False}
        with (
            query_name_scope("saas.interactive_execution.read_current_run"),
            self._sessions.begin() as db,
        ):
            ExecutionControlPlane._apply_request_context(db, request)
            query = (
                sa.select(RunRecord)
                .where(
                    RunRecord.tenant_id == request.tenant_id,
                    RunRecord.space_id == request.space_id,
                    RunRecord.project_id == project_id,
                    RunRecord.session_id == session_id,
                    RunRecord.queue_class == INTERACTIVE_QUEUE_CLASS,
                )
                .order_by(RunRecord.created_at.desc(), RunRecord.id.desc())
            )
            physical_run_id = db.scalar(
                query.with_only_columns(RunRecord.id).where(RunRecord.fence_token > 0).limit(1)
            )
            if event_type == "interrupt":
                query = query.where(RunRecord.status.not_in(TERMINAL_RUN_STATUSES))
            else:
                query = query.limit(1)
            runs = list(db.scalars(query))
        if event_type == "interrupt":
            # Cancel every outstanding input, not only the newest queued message.
            for run in runs:
                mutation = self._execution.request_cancel(
                    request,
                    project_id=project_id,
                    run_id=run.id,
                    reason="User interrupted the interactive session",
                )
                if mutation.status == "cancelling":
                    physical_run_id = run.id
        return {
            "queued": False,
            **({"physical_run_id": str(physical_run_id)} if physical_run_id else {}),
            **({"run_id": str(runs[0].id)} if runs else {}),
        }
