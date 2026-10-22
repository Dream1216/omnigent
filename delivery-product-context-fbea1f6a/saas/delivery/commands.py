"""Source resolution shared by session and compatibility entry points."""

from typing import Any
from uuid import UUID

from fastapi import Request

from saas.delivery.access import DeliveryAccess

READ = frozenset({"build:read", "snapshot:read", "deployment:read"})
BUILD = READ | {"build:create", "snapshot:create", "snapshot:promote", "deployment:create"}


async def build_run(
    access: DeliveryAccess,
    request: Request,
    project_id: UUID,
    body: dict[str, Any],
    key: str,
) -> Any:
    project = access.binding(project_id)
    current = access.context(request, project, "run.create", "preview.open")
    snapshot = await access.call(
        current,
        BUILD,
        "POST",
        "/v1/source-snapshots/from-checkpoint",
        key=key,
        body={
            "run_id": body["run_id"],
            "context_path": body.get("context_path", "."),
            "environment_id": project.preview_environment,
        },
    )
    options = {
        k: body[k] for k in ("mode", "dockerfile_path", "service_port", "health_path") if k in body
    }
    return await access.call(
        current,
        BUILD,
        "POST",
        "/v1/deliveries",
        key=key,
        body={
            **options,
            "snapshot_id": snapshot["snapshot"]["id"],
            "environment_id": project.preview_environment,
            "ttl_seconds": 3600,
        },
    )
