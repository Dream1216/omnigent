"""Browser commands derive all deployment authority from the current SaaS context."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.execution_models import RunRecord
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.preview_models import PreviewExecutionRecord
from saas.control_plane.resolver import SqlAlchemyContextResolver
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.delivery.access import DeliveryAccess
from saas.delivery.client import DeliveryClient
from saas.delivery.sessions import session_runs

Key = Annotated[
    str,
    Header(
        alias="Idempotency-Key",
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    ),
]
READ = frozenset({"build:read", "snapshot:read", "deployment:read"})
BUILD = READ | {"build:create", "snapshot:promote", "deployment:create"}


class BuildOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["auto", "static", "dockerfile"] = "auto"
    dockerfile_path: str = Field(default="Dockerfile", max_length=512)
    service_port: int = Field(default=8080, ge=1, le=65535)
    health_path: str = Field(default="/", pattern=r"^/[^\r\n]*$", max_length=512)


class BuildBody(BuildOptions):
    snapshot_id: UUID


class RunBuildBody(BuildOptions):
    run_id: UUID
    context_path: str = Field(default=".", min_length=1, max_length=512)


class PromoteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_target_generation: int = Field(ge=0)


class RollbackBody(PromoteBody):
    target_release_id: UUID
    expected_target_generation: int = Field(ge=1)


class CancelBuildBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)


def create_delivery_router(
    *,
    auth: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    sessions: sessionmaker[Session],
    client: DeliveryClient | None,
    preview_enabled: bool = False,
) -> APIRouter:
    router = APIRouter()

    access = DeliveryAccess(auth, resolver, sessions, client)
    binding, context, call = access.binding, access.context, access.call

    @router.get("/delivery/sessions/{session_id}")
    def session_delivery(session_id: str, request: Request, response: Response) -> dict[str, Any]:
        if auth.get_principal(request) is None:
            raise HTTPException(401, detail={"code": "authentication_required"})
        response.headers["Cache-Control"] = "no-store"
        runs = session_runs(access, request, session_id)
        result: dict[str, Any] = {
            "runs": runs,
            "preview_enabled": preview_enabled,
            "preview": None,
        }
        if runs:
            source = runs[0]
            current = context(request, binding(UUID(source["project_id"])), "preview.open")
            with sessions() as db:
                apply_rls_context(
                    db,
                    RlsContext(
                        actor_id=current.actor_id,
                        tenant_id=current.tenant_id,
                        space_id=current.space_id,
                        project_id=current.project_id,
                    ),
                )
                active = db.scalar(
                    select(PreviewExecutionRecord)
                    .where(
                        PreviewExecutionRecord.tenant_id == current.tenant_id,
                        PreviewExecutionRecord.space_id == current.space_id,
                        PreviewExecutionRecord.project_id == current.project_id,
                        PreviewExecutionRecord.source_run_id == UUID(source["id"]),
                        PreviewExecutionRecord.status.in_(
                            (
                                "requested",
                                "queued",
                                "materializing",
                                "starting",
                                "ready",
                                "stopping",
                            )
                        ),
                    )
                    .order_by(PreviewExecutionRecord.created_at.desc())
                    .limit(1)
                )
                if active is not None:
                    result["preview"] = str(active.id)
        return result

    @router.get("/delivery", include_in_schema=False)
    def page() -> FileResponse:
        return FileResponse(
            Path(__file__).parents[1] / "admin_ui" / "delivery.html",
            headers={
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'"
                ),
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            },
        )

    @router.get("/delivery/assets/{name}", include_in_schema=False)
    def asset(name: str) -> FileResponse:
        if name not in {"delivery.js", "delivery.css"}:
            raise HTTPException(404)
        return FileResponse(Path(__file__).parents[1] / "admin_ui" / name)

    @router.get("/delivery/.well-known/jwks.json")
    def jwks() -> dict[str, Any]:
        if client is None:
            raise HTTPException(503)
        return client.jwks()

    @router.get("/delivery/projects")
    def projects(request: Request, response: Response) -> dict[str, Any]:
        if auth.get_principal(request) is None:
            raise HTTPException(401, detail={"code": "authentication_required"})
        response.headers["Cache-Control"] = "no-store"
        values = []
        for project in () if client is None else client.config.projects:
            try:
                context(request, project)
            except HTTPException:
                continue
            actions = {}
            for action, required in {
                "build": ("run.create", "preview.open"),
                "publish": ("environment.manage",),
                "rollback": ("environment.manage",),
            }.items():
                try:
                    context(request, project, *required)
                    actions[action] = True
                except HTTPException:
                    actions[action] = False
            values.append(
                {
                    "id": str(project.project_id),
                    "name": project.name,
                    "tenant_id": str(project.tenant_id),
                    "space_id": str(project.space_id),
                    "preview_environment": project.preview_environment,
                    "production_environment": project.production_environment,
                    "actions": actions,
                }
            )
        return {
            "configured": client is not None,
            "projects": values,
            "live_preview_enabled": preview_enabled,
        }

    @router.get("/delivery/projects/{project_id}")
    async def overview(project_id: UUID, request: Request, response: Response) -> dict[str, Any]:
        project = binding(project_id)
        current = context(request, project)
        response.headers["Cache-Control"] = "no-store"
        deliveries, releases, production, snapshots, history, builds = await asyncio.gather(
            call(current, READ, "GET", "/v1/deliveries"),
            call(
                current, READ, "GET", f"/v1/releases?environment_id={project.preview_environment}"
            ),
            call(
                current,
                READ,
                "GET",
                f"/v1/releases?environment_id={project.production_environment}&limit=1",
            ),
            call(current, READ, "GET", "/v1/source-snapshots"),
            call(
                current,
                READ,
                "GET",
                f"/v1/releases/verified-history?environment_id={project.production_environment}",
            ),
            call(current, READ, "GET", "/v1/builds"),
        )
        return {
            "deliveries": deliveries,
            "releases": production["releases"] + releases["releases"],
            "history": history["releases"],
            "builds": builds["builds"],
            "snapshots": [
                value["snapshot"] for value in snapshots if value["snapshot"]["status"] == "ready"
            ],
        }

    @router.post("/delivery/projects/{project_id}/build", status_code=202)
    async def build(
        project_id: UUID, body: BuildBody, request: Request, idempotency_key: Key
    ) -> Any:
        project = binding(project_id)
        current = context(request, project, "run.create", "preview.open")
        return await call(
            current,
            BUILD,
            "POST",
            "/v1/deliveries",
            key=idempotency_key,
            body={
                **body.model_dump(mode="json"),
                "environment_id": project.preview_environment,
                "ttl_seconds": 3600,
            },
        )

    @router.post("/delivery/projects/{project_id}/build-from-run", status_code=202)
    async def build_from_run(
        project_id: UUID, body: RunBuildBody, request: Request, idempotency_key: Key
    ) -> Any:
        from saas.delivery.commands import build_run

        return await build_run(
            access, request, project_id, body.model_dump(mode="json"), idempotency_key
        )

    @router.post(
        "/delivery/projects/{project_id}/deliveries/{delivery_id}/cancel", status_code=202
    )
    async def cancel_delivery(
        project_id: UUID, delivery_id: UUID, body: CancelBuildBody, request: Request
    ) -> Any:
        current = context(request, binding(project_id), "run.create")
        return await call(
            current,
            READ | {"build:cancel"},
            "POST",
            f"/v1/deliveries/{delivery_id}/cancel",
            body=body.model_dump(),
        )

    @router.post("/delivery/projects/{project_id}/builds/{build_id}/cancel", status_code=202)
    async def cancel_build(
        project_id: UUID, build_id: UUID, body: CancelBuildBody, request: Request
    ) -> Any:
        current = context(request, binding(project_id), "run.create")
        return await call(
            current,
            READ | {"build:cancel"},
            "POST",
            f"/v1/builds/{build_id}/cancel",
            body=body.model_dump(),
        )

    @router.post("/delivery/projects/{project_id}/releases/{release_id}/promote", status_code=202)
    async def promote(
        project_id: UUID,
        release_id: UUID,
        body: PromoteBody,
        request: Request,
        idempotency_key: Key,
    ) -> Any:
        project = binding(project_id)
        current = context(request, project, "environment.manage")
        permissions = READ | {"deployment:create", "deployment:promote"}
        return await call(
            current,
            permissions,
            "POST",
            f"/v1/releases/{release_id}/promote",
            body={**body.model_dump(), "environment_id": project.production_environment},
            key=idempotency_key,
        )

    @router.post("/delivery/projects/{project_id}/releases/{release_id}/rollback", status_code=202)
    async def rollback(
        project_id: UUID,
        release_id: UUID,
        body: RollbackBody,
        request: Request,
        idempotency_key: Key,
    ) -> Any:
        current = context(request, binding(project_id), "environment.manage")
        return await call(
            current,
            READ | {"deployment:create", "deployment:rollback"},
            "POST",
            f"/v1/releases/{release_id}/rollback",
            body=body.model_dump(mode="json"),
            key=idempotency_key,
        )

    @router.get("/delivery/projects/{project_id}/previews/{preview_id}/open")
    async def open_preview(
        project_id: UUID, preview_id: UUID, request: Request, response: Response
    ) -> dict[str, str]:
        project = binding(project_id)
        current = context(request, project, "preview.open")
        response.headers["Cache-Control"] = "no-store"
        preview = (await call(current, READ, "GET", f"/v1/release-previews/{preview_id}"))[
            "preview"
        ]
        if preview["status"] != "ready":
            raise HTTPException(409, detail={"code": "preview_endpoint_unavailable"})
        expires_at = datetime.fromisoformat(preview["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(409, detail={"code": "preview_expired"})
        domain_path = (
            f"/v1/domains/{project.preview_domain_binding_id}"
            if project.preview_domain_binding_id
            else f"/v1/release-previews/{preview_id}/domain"
        )
        try:
            domain = (
                await call(
                    current,
                    READ | {"domain:read"},
                    "GET",
                    domain_path,
                )
            )["domain"]
        except HTTPException as error:
            if error.status_code == 404:
                raise HTTPException(
                    409, detail={"code": "preview_endpoint_unavailable"}
                ) from error
            raise
        if (
            domain["status"] != "ready"
            or domain["environment_id"] != preview["environment_id"]
            or domain["target_generation"] != preview["target_generation"]
            or domain["git_revision"] != preview["git_revision"]
            or datetime.fromisoformat(domain["certificate_not_after"])
            <= datetime.now(timezone.utc)
        ):
            raise HTTPException(409, detail={"code": "preview_endpoint_stale"})
        hostname = domain["hostname"]
        primary = request.url.hostname or ""
        if (
            not hostname
            or hostname == primary
            or hostname.endswith("." + primary)
            or primary.endswith("." + hostname)
            or urlsplit("https://" + hostname).hostname != hostname
        ):
            raise HTTPException(409, detail={"code": "preview_origin_invalid"})
        return {"url": "https://" + hostname}

    @router.get("/delivery/projects/{project_id}/runs")
    def source_runs(project_id: UUID, request: Request) -> list[dict[str, str]]:
        current = context(request, binding(project_id), "preview.open")
        with sessions() as session:
            apply_rls_context(
                session,
                RlsContext(
                    actor_id=current.actor_id,
                    tenant_id=current.tenant_id,
                    space_id=current.space_id,
                    project_id=project_id,
                ),
            )
            runs = session.scalars(
                select(RunRecord)
                .where(
                    RunRecord.tenant_id == current.tenant_id,
                    RunRecord.space_id == current.space_id,
                    RunRecord.project_id == project_id,
                    RunRecord.created_by == current.actor_id,
                    RunRecord.status == "succeeded",
                )
                .order_by(RunRecord.created_at.desc())
                .limit(50)
            )
            return [{"id": str(run.id), "created_at": run.created_at.isoformat()} for run in runs]

    return router
