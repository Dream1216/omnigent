"""Cookie-authenticated workspace intent endpoints, independent of tenant scope."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from saas.control_plane.onboarding import (
    OnboardingError,
    TenantCreationIntentService,
    WorkspaceCreationAccepted,
)
from saas.control_plane.onboarding_http import OnboardingStatusResponse, _status_payload
from saas.control_plane.onboarding_status import OnboardingStatusError, OnboardingStatusService

if TYPE_CHECKING:
    from saas.control_plane.http_auth import SaasAuthProvider


class WorkspaceCreationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tenant_name: str = Field(min_length=1, max_length=256)
    plan_key: str | None = Field(default=None, min_length=1, max_length=64)
    home_region: str | None = Field(default=None, min_length=1, max_length=64)


def create_workspace_router(
    *,
    auth_provider: SaasAuthProvider,
    creation: TenantCreationIntentService,
    status: OnboardingStatusService,
) -> APIRouter:
    router = APIRouter(prefix="/onboarding/workspaces")

    def actor(request: Request) -> UUID:
        _, source = auth_provider.extract_token(request)
        principal = auth_provider.get_principal(request) if source == "cookie" else None
        if principal is None or "authorization" in request.headers:
            raise HTTPException(
                401,
                detail={"code": "authentication_required"},
                headers={"Cache-Control": "private, no-store"},
            )
        return principal.session.user_id

    @router.post("", status_code=202)
    def create(
        body: WorkspaceCreationRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        user_id = actor(request)
        response.headers["Cache-Control"] = "private, no-store"
        try:
            accepted = creation.create(
                actor_id=user_id,
                tenant_name=body.tenant_name,
                plan_key=body.plan_key,
                home_region=body.home_region,
                idempotency_key=idempotency_key,
            )
        except OnboardingError as error:
            status_code = (
                429
                if error.code == "workspace_creation_limited"
                else (403 if error.code in {"verified_email_required", "user_inactive"} else 409)
            )
            raise HTTPException(
                status_code,
                detail={"code": error.code, "message": str(error)},
                headers={"Cache-Control": "private, no-store"},
            ) from error
        response.headers["Location"] = f"/saas/onboarding/workspaces/{accepted.intent_id}/status"
        return _accepted(accepted)

    @router.get("")
    def list_workspaces(request: Request, response: Response) -> list[dict[str, object]]:
        user_id = actor(request)
        response.headers["Cache-Control"] = "private, no-store"
        return [_accepted(value) for value in creation.list_for_actor(user_id)]

    @router.get(
        "/{intent_id}/status",
        response_model=OnboardingStatusResponse,
        response_model_exclude_none=True,
    )
    def workspace_status(
        intent_id: UUID, request: Request, response: Response
    ) -> OnboardingStatusResponse:
        user_id = actor(request)
        response.headers["Cache-Control"] = "private, no-store"
        try:
            return _status_payload(status.for_workspace(user_id, intent_id))
        except OnboardingStatusError as error:
            raise HTTPException(
                404, detail={"code": error.code}, headers={"Cache-Control": "private, no-store"}
            ) from error

    return router


def _accepted(value: WorkspaceCreationAccepted) -> dict[str, object]:
    return {
        "id": str(value.intent_id),
        "name": value.tenant_name,
        "created_at": value.created_at.isoformat(),
        "status_url": f"/saas/onboarding/workspaces/{value.intent_id}/status",
        "replayed": value.replayed,
    }
