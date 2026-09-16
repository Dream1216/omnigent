"""Resolve a browser conversation to a completed, scoped SaaS Run."""

from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import or_, select

from saas.control_plane.db_models import RuntimeResourceBindingRecord
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.delivery.access import DeliveryAccess


def session_runs(
    access: DeliveryAccess,
    request: Request,
    session_id: str,
    project_id: UUID | None = None,
    *,
    action: str = "preview.open",
) -> list[dict[str, str]]:
    if access.client is None:
        return []
    candidates = []
    for project in access.client.config.projects:
        if project_id is not None and project_id != project.project_id:
            continue
        try:
            current = access.context(request, project, action)
        except HTTPException:
            continue
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
    return sorted(candidates, key=lambda item: item["created_at"], reverse=True)
