"""Compatibility wire format backed only by current SaaS authority and DCP.

The old browser bookmark redirects to the current workbench. API callers may
keep the old paths; approval and execution now follow DCP admission policy.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy import select

from saas.control_plane.db_models import RuntimeResourceBindingRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.delivery.access import DeliveryAccess
from saas.delivery.commands import BUILD, READ, build_run
from saas.delivery.http import BuildOptions
from saas.delivery.sessions import session_runs


class LegacyBuild(BuildOptions):
    project_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    environment: Literal["preview", "production"] = "preview"
    context_path: str = Field(default=".", min_length=1, max_length=512)
    target_platform: Literal["linux/amd64"] = "linux/amd64"
    snapshot_ref: str | None = None
    snapshot_digest: str | None = None


class LegacyRelease(BuildOptions):
    project_id: str = Field(min_length=1, max_length=128)
    environment: Literal["preview", "production"]
    source_revision: str = Field(min_length=7, max_length=128)
    artifact_ref: str = Field(pattern=r"^[^\s@]+@sha256:[0-9a-f]{64}$", max_length=1024)
    source_snapshot_digest: str | None = None
    provider: Literal["kubernetes"] = "kubernetes"


def _key(request: Request, fallback: str) -> str:
    value = request.headers.get("Idempotency-Key")
    if value is not None:
        if not 1 <= len(value) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise HTTPException(422, detail={"code": "invalid_idempotency_key"})
        return value
    return "legacy:" + hashlib.sha256(fallback.encode()).hexdigest()


def _wire(record: dict[str, Any], project_id: UUID, *, build: bool = False) -> dict[str, Any]:
    stage = record["status"]
    status = {
        "ready": "succeeded",
        "snapshot": "queued",
        "requested": "queued",
        "build": "running",
        "release": "running",
        "reconciling": "running",
        "superseded": "cancelled",
    }.get(stage, stage)
    created = record.get("created_at")
    epoch = datetime.fromisoformat(created).timestamp() if isinstance(created, str) else created
    return {
        **record,
        "object": "build_job" if build else "deployment",
        "project_id": str(project_id),
        "status": status,
        "stage": stage,
        "created_at": epoch,
        "updated_at": epoch,
        "environment": record.get("environment_type", "preview"),
        "control_plane": "dcp",
        "deployment_id": record.get("release_id"),
        "progress_percent": 100 if status in {"succeeded", "failed", "cancelled"} else 0,
        "source_revision": "snapshot:" + (record.get("source_snapshot_digest") or ""),
        "error": record.get("error_code"),
        "execution_mode": "dcp_managed",
    }


def create_legacy_delivery_router(access: DeliveryAccess) -> APIRouter:
    router = APIRouter()

    def scopes(request: Request):
        if access.auth.get_principal(request) is None:
            raise HTTPException(401, detail={"code": "authentication_required"})
        if access.client is None:
            raise HTTPException(503, detail={"code": "delivery_not_configured"})
        result = []
        for project in access.client.config.projects:
            try:
                result.append((project, access.context(request, project)))
            except HTTPException as error:
                if error.status_code != 404:
                    raise
        return result

    def project_for(request: Request, value: str):
        for project, current in scopes(request):
            if value in {str(project.project_id), project.project_id.hex}:
                return project
            with access.sessions() as db:
                apply_rls_context(
                    db,
                    RlsContext(
                        actor_id=current.actor_id,
                        tenant_id=current.tenant_id,
                        space_id=current.space_id,
                        project_id=current.project_id,
                    ),
                )
                mapped = db.scalar(
                    select(RuntimeResourceBindingRecord.id).where(
                        RuntimeResourceBindingRecord.tenant_id == current.tenant_id,
                        RuntimeResourceBindingRecord.space_id == current.space_id,
                        RuntimeResourceBindingRecord.project_id == current.project_id,
                        RuntimeResourceBindingRecord.resource_type == "project",
                        RuntimeResourceBindingRecord.runtime_resource_id == value,
                        RuntimeResourceBindingRecord.status == "active",
                    )
                )
                if mapped is not None:
                    return project
        raise HTTPException(404, detail={"code": "delivery_scope_unavailable"})

    async def locate(request: Request, kind: str, identifier: str):
        try:
            identifier = str(UUID(identifier))
        except ValueError as error:
            raise HTTPException(404) from error
        for project, current in scopes(request):
            try:
                result = await access.call(current, READ, "GET", f"/v1/{kind}/{identifier}")
                return project, result.get("release", result.get("build", result))
            except HTTPException as error:
                if error.status_code != 404:
                    raise
        raise HTTPException(404, detail={"code": "delivery_resource_unavailable"})

    @router.get("/deployments")
    @router.get("/builds")
    async def listing(request: Request, response: Response, project_id: str | None = None):
        response.headers["Cache-Control"] = "no-store"
        is_build = request.url.path.endswith("/builds")
        selected = project_for(request, project_id) if project_id else None
        data = []
        for project, current in scopes(request):
            if selected is not None and project != selected:
                continue
            kind = "builds" if is_build else "releases"
            values = await access.call(current, READ, "GET", f"/v1/{kind}")
            data.extend(_wire(value, project.project_id, build=is_build) for value in values[kind])
            if is_build:
                deliveries = await access.call(current, READ, "GET", "/v1/deliveries")
                # Stable delivery IDs remain pollable before the Build exists.
                data.extend(
                    _wire(value, project.project_id, build=True)
                    for value in deliveries
                    if not value["build_id"]
                )
        return {"data": sorted(data, key=lambda item: item["created_at"], reverse=True)}

    @router.post("/deployments/build", status_code=202)
    async def build(request: Request, body: LegacyBuild):
        project = project_for(request, body.project_id)
        runs = session_runs(
            access, request, body.session_id, project.project_id, action="run.create"
        )
        if not runs:
            raise HTTPException(409, detail={"code": "completed_session_run_required"})
        # Production always promotes a verified preview through the publish action.
        if body.environment != "preview":
            raise HTTPException(422, detail={"code": "build_preview_then_promote"})
        intent = {**body.model_dump(mode="json"), "run_id": runs[0]["id"]}
        if body.snapshot_ref is not None or body.snapshot_digest is not None:
            current = access.context(request, project, "run.create", "preview.open")
            snapshots = await access.call(current, READ, "GET", "/v1/source-snapshots")
            source = next(
                (
                    item["snapshot"]
                    for item in snapshots
                    if item["snapshot"]["status"] == "ready"
                    and item["snapshot"]["oci_artifact_ref"] == body.snapshot_ref
                    and item["snapshot"]["archive_digest"] == body.snapshot_digest
                ),
                None,
            )
            if source is None:
                raise HTTPException(409, detail={"code": "verified_snapshot_required"})
            result = await access.call(
                current,
                BUILD,
                "POST",
                "/v1/deliveries",
                key=_key(request, json.dumps(intent, sort_keys=True)),
                body={
                    "snapshot_id": source["id"],
                    "environment_id": project.preview_environment,
                    **{
                        k: intent[k]
                        for k in ("mode", "dockerfile_path", "service_port", "health_path")
                    },
                },
            )
            return {"build": _wire(result, project.project_id, build=True), "reused": False}
        result = await build_run(
            access,
            request,
            project.project_id,
            intent,
            _key(request, json.dumps(intent, sort_keys=True)),
        )
        return {"build": _wire(result, project.project_id, build=True), "reused": False}

    @router.post("/deployments", status_code=201)
    async def create(request: Request, body: LegacyRelease):
        project = project_for(request, body.project_id)
        current = access.context(
            request,
            project,
            "environment.manage" if body.environment == "production" else "preview.open",
        )
        builds = (await access.call(current, READ, "GET", "/v1/builds?limit=200"))["builds"]
        source = next(
            (
                b
                for b in builds
                if b["status"] == "ready" and b["artifact_ref"] == body.artifact_ref
            ),
            None,
        )
        if source is None or (
            body.source_snapshot_digest
            and body.source_snapshot_digest != source["snapshot_digest"]
        ):
            raise HTTPException(409, detail={"code": "verified_build_required"})
        spec = {
            "environment_id": project.production_environment
            if body.environment == "production"
            else project.preview_environment,
            "environment_type": body.environment,
            "workload_kind": "stateless_http",
            "artifact_ref": body.artifact_ref,
            "source_snapshot_digest": source["snapshot_digest"],
            "service_port": body.service_port,
            "health_path": body.health_path,
        }
        result = await access.call(
            current,
            READ | {"deployment:create"},
            "POST",
            "/v1/releases",
            key=_key(request, json.dumps(spec, sort_keys=True)),
            body={"spec": spec},
        )
        return _wire(result["release"], project.project_id)

    @router.get("/deployments/{identifier}")
    @router.get("/builds/{identifier}")
    async def get(request: Request, identifier: str):
        is_build = "/builds/" in request.url.path
        try:
            project, record = await locate(
                request, "builds" if is_build else "releases", identifier
            )
        except HTTPException as error:
            if not is_build or error.status_code != 404:
                raise
            project, record = await locate(request, "deliveries", identifier)
        return _wire(record, project.project_id, build=is_build)

    @router.get("/deployments/{identifier}/events")
    @router.get("/builds/{identifier}/events")
    async def events(request: Request, identifier: str):
        record = await get(request, identifier)
        return {
            "data": [
                {
                    "id": record["id"] + ":" + str(record["aggregate_version"]),
                    "kind": record["stage"],
                    "message": record["error"] or record["stage"],
                    "created_at": record["updated_at"],
                }
            ]
        }

    @router.post("/builds/{identifier}/{action}", status_code=202)
    async def build_action(request: Request, identifier: str, action: Literal["cancel", "retry"]):
        try:
            project, record = await locate(request, "deliveries", identifier)
        except HTTPException as error:
            if error.status_code != 404:
                raise
            project, build_record = await locate(request, "builds", identifier)
            current = access.context(request, project, "run.create")
            records = await access.call(current, READ, "GET", "/v1/deliveries?limit=200")
            record = next((d for d in records if d["build_id"] == build_record["id"]), None)
            if record is None:
                if action == "cancel":
                    result = await access.call(
                        current,
                        READ | {"build:cancel"},
                        "POST",
                        f"/v1/builds/{build_record['id']}/cancel",
                        body={"expected_version": build_record["aggregate_version"]},
                    )
                    return _wire(result["build"], project.project_id, build=True)
                spec = {
                    k: build_record[k]
                    for k in (
                        "snapshot_ref",
                        "snapshot_digest",
                        "mode",
                        "dockerfile_path",
                        "target_platform",
                    )
                }
                result = await access.call(
                    current,
                    BUILD,
                    "POST",
                    "/v1/builds",
                    body={"spec": spec},
                    key=_key(request, "retry:" + build_record["id"]),
                )
                return _wire(result["build"], project.project_id, build=True)
        current = access.context(request, project, "run.create", "preview.open")
        if action == "cancel":
            result = await access.call(
                current,
                READ | {"build:cancel"},
                "POST",
                f"/v1/deliveries/{record['id']}/cancel",
                body={"expected_version": record["aggregate_version"]},
            )
        else:
            if record["status"] not in {"failed", "cancelled"}:
                raise HTTPException(409, detail={"code": "build_not_retryable"})
            result = await access.call(
                current,
                BUILD,
                "POST",
                "/v1/deliveries",
                body=record["spec"],
                key=_key(request, "retry:" + record["id"]),
            )
        return _wire(result, project.project_id, build=True)

    @router.post("/deployments/{identifier}/{action}")
    async def release_action(
        request: Request,
        identifier: str,
        action: Literal["approve", "execute", "promote", "rollback"],
    ):
        project, record = await locate(request, "releases", identifier)
        current = access.context(
            request,
            project,
            "environment.manage"
            if action != "execute" or record["environment_type"] == "production"
            else "preview.open",
        )
        if action in {"approve", "execute"}:
            if record["status"] in {"awaiting_approval", "failed", "cancelled", "superseded"}:
                raise HTTPException(
                    409,
                    detail={"code": "dcp_policy_or_terminal_state", "status": record["status"]},
                )
            return _wire(record, project.project_id)
        if action == "promote":
            latest = (
                await access.call(
                    current,
                    READ,
                    "GET",
                    f"/v1/releases?environment_id={project.production_environment}&limit=1",
                )
            )["releases"]
            body = {
                "environment_id": project.production_environment,
                "expected_target_generation": latest[0]["target_generation"] if latest else 0,
            }
        else:
            history = (
                await access.call(
                    current,
                    READ,
                    "GET",
                    f"/v1/releases/verified-history?environment_id={record['environment_id']}",
                )
            )["releases"]
            older = [
                r
                for r in history
                if r["created_at"] < record["created_at"] and r["id"] != record["id"]
            ]
            if not older:
                raise HTTPException(409, detail={"code": "rollback_history_unavailable"})
            target = max(older, key=lambda r: (r["created_at"], r["id"]))
            body = {
                "target_release_id": target["id"],
                "expected_target_generation": record["target_generation"],
            }
        result = await access.call(
            current,
            READ | {"deployment:create", "deployment:" + action},
            "POST",
            f"/v1/releases/{record['id']}/{action}",
            body=body,
            key=_key(request, action + ":" + record["id"]),
        )
        return _wire(result["release"], project.project_id)

    return router
