"""Resolve a browser conversation to a completed, scoped SaaS Run."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import or_, select

from saas.control_plane.db_models import RuntimeResourceBindingRecord
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.delivery.access import DeliveryAccess


@dataclass(frozen=True)
class SessionRunSelection:
    runs: list[dict[str, str]]
    diagnostic_code: str | None = None


def select_session_runs(
    access: DeliveryAccess,
    request: Request,
    session_id: str,
    project_id: UUID | None = None,
    *,
    action: str = "preview.open",
) -> SessionRunSelection:
    if access.client is None:
        return SessionRunSelection([], "delivery_not_configured")
    candidates = []
    authorized_projects, bound_session = 0, False
    for project in access.client.config.projects:
        if project_id is not None and project_id != project.project_id:
            continue
        try:
            current = access.context(request, project, action)
        except HTTPException:
            continue
        authorized_projects += 1
        with access.sessions() as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=current.actor_id,
                    tenant_id=current.tenant_id,
                    space_id=current.space_id,
                    project_id=project.project_id,
                ),
            )
            try:
                logical_id = UUID(session_id)
            except ValueError:
                logical_id = None
            mappings = select(RuntimeResourceBindingRecord.saas_resource_id).where(
                RuntimeResourceBindingRecord.tenant_id == current.tenant_id,
                RuntimeResourceBindingRecord.space_id == current.space_id,
                RuntimeResourceBindingRecord.project_id == project.project_id,
                RuntimeResourceBindingRecord.resource_type.in_(("session", "conversation")),
                RuntimeResourceBindingRecord.runtime_resource_id == session_id,
                RuntimeResourceBindingRecord.status == "active",
            )
            sessions = select(ExecutionSessionRecord.id).where(
                ExecutionSessionRecord.tenant_id == current.tenant_id,
                ExecutionSessionRecord.space_id == current.space_id,
                ExecutionSessionRecord.project_id == project.project_id,
                ExecutionSessionRecord.created_by == current.actor_id,
                or_(
                    ExecutionSessionRecord.id == logical_id,
                    ExecutionSessionRecord.id.in_(mappings),
                ),
            )
            bound_session = bound_session or bool(db.scalar(select(sessions.exists())))
            runs = db.scalars(
                select(RunRecord)
                .where(
                    RunRecord.session_id.in_(sessions),
                    RunRecord.tenant_id == current.tenant_id,
                    RunRecord.space_id == current.space_id,
                    RunRecord.project_id == project.project_id,
                    RunRecord.created_by == current.actor_id,
                    RunRecord.status == "succeeded",
                    RunRecord.queue_class != "preview",
                )
                .order_by(RunRecord.created_at.desc())
                .limit(50)
            )
            candidates.extend(
                {
                    "id": str(run.id),
                    "session_id": str(run.session_id),
                    "project_id": str(project.project_id),
                    "tenant_id": str(project.tenant_id),
                    "space_id": str(project.space_id),
                    "created_at": run.created_at.isoformat(),
                }
                for run in runs
            )
    if project_id is None and len({item["project_id"] for item in candidates}) > 1:
        raise HTTPException(409, detail={"code": "session_project_ambiguous"})
    diagnostic = None
    if not candidates:
        diagnostic = (
            "preview_scope_unavailable"
            if authorized_projects == 0 and access.client.config.projects
            else "preview_source_unavailable"
            if bound_session
            else "preview_project_binding_missing"
        )
    return SessionRunSelection(
        sorted(candidates, key=lambda item: item["created_at"], reverse=True), diagnostic
    )


def session_runs(
    access: DeliveryAccess,
    request: Request,
    session_id: str,
    project_id: UUID | None = None,
    *,
    action: str = "preview.open",
) -> list[dict[str, str]]:
    return select_session_runs(access, request, session_id, project_id, action=action).runs
