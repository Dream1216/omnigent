"""Customer Realm approval API for tenant-bound Staff support access."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from saas.control_plane.http_auth import SaasAuthProvider, SaasPrincipal
from saas.control_plane.platform_governed_access import (
    PlatformGovernedAccessService,
    SupportGrantView,
    TenantSupportActor,
)
from saas.control_plane.platform_security import PlatformSecurityError


class TenantSupportDecisionBody(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


def create_tenant_support_access_router(
    *,
    auth_provider: SaasAuthProvider,
    governed_access: PlatformGovernedAccessService,
) -> APIRouter:
    """Expose only tenant-visible Grant metadata and explicit approval decisions."""

    router = APIRouter()

    @router.get("/tenants/{tenant_id}/support-access-grants")
    def list_support_access_grants(
        tenant_id: UUID,
        request: Request,
        response: Response,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = governed_access.list_tenant_support_grants(
                TenantSupportActor(
                    actor_id=principal.session.user_id,
                    tenant_id=tenant_id,
                    security_version=principal.session.security_version,
                ),
                cursor=cursor,
                limit=limit,
            )
        except PlatformSecurityError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [_grant_payload(value) for value in values],
            "next_cursor": str(values[-1].grant_id) if len(values) == limit else None,
            "content_access": "none",
        }

    @router.post("/tenants/{tenant_id}/support-access-grants/{grant_id}/approve")
    def approve_support_access_grant(
        tenant_id: UUID,
        grant_id: UUID,
        body: TenantSupportDecisionBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        return _decide(
            auth_provider=auth_provider,
            governed_access=governed_access,
            tenant_id=tenant_id,
            grant_id=grant_id,
            decision="approve",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @router.post("/tenants/{tenant_id}/support-access-grants/{grant_id}/reject")
    def reject_support_access_grant(
        tenant_id: UUID,
        grant_id: UUID,
        body: TenantSupportDecisionBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        return _decide(
            auth_provider=auth_provider,
            governed_access=governed_access,
            tenant_id=tenant_id,
            grant_id=grant_id,
            decision="reject",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @router.post("/tenants/{tenant_id}/support-access-grants/{grant_id}/revoke")
    def revoke_support_access_grant(
        tenant_id: UUID,
        grant_id: UUID,
        body: TenantSupportDecisionBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            value = governed_access.revoke_support_grant_by_customer(
                TenantSupportActor(
                    actor_id=principal.session.user_id,
                    tenant_id=tenant_id,
                    security_version=principal.session.security_version,
                ),
                grant_id=grant_id,
                expected_version=body.expected_version,
                reason=body.reason,
                reauthenticated_at=principal.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except PlatformSecurityError as error:
            raise _http_error(error) from error
        return _grant_payload(value)

    return router


def _decide(
    *,
    auth_provider: SaasAuthProvider,
    governed_access: PlatformGovernedAccessService,
    tenant_id: UUID,
    grant_id: UUID,
    decision: Literal["approve", "reject"],
    body: TenantSupportDecisionBody,
    request: Request,
    idempotency_key: str,
) -> dict[str, object]:
    principal = _principal(auth_provider, request)
    try:
        value = governed_access.decide_customer_approval(
            TenantSupportActor(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                security_version=principal.session.security_version,
            ),
            grant_id=grant_id,
            expected_version=body.expected_version,
            decision=decision,
            reason=body.reason,
            reauthenticated_at=principal.session.authenticated_at,
            idempotency_key=idempotency_key,
        )
    except PlatformSecurityError as error:
        raise _http_error(error) from error
    return _grant_payload(value)


def _principal(auth_provider: SaasAuthProvider, request: Request) -> SaasPrincipal:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return principal


def _http_error(error: PlatformSecurityError) -> HTTPException:
    if error.code.endswith("_not_found"):
        status = 404
    elif error.code.endswith("_conflict") or error.code.endswith("_expired"):
        status = 409
    elif "permission" in error.code or "fresh_auth" in error.code:
        status = 403
    else:
        status = 400
    return HTTPException(
        status_code=status,
        detail={"code": error.code, "message": str(error)},
    )


def _grant_payload(value: SupportGrantView) -> dict[str, object]:
    return {
        "grant_id": str(value.grant_id),
        "operation_id": str(value.operation_id),
        "tenant_id": str(value.tenant_id),
        "requested_by_principal_id": str(value.requested_by_principal_id),
        "mode": value.mode,
        "scopes": list(value.scopes),
        "project_ids": [str(item) for item in value.project_ids],
        "status": value.status,
        "version": value.version,
        "customer_approval_required": value.customer_approval_required,
        "customer_approved_by_user_id": (
            str(value.customer_approved_by_user_id)
            if value.customer_approved_by_user_id is not None
            else None
        ),
        "staff_approved_by_principal_id": (
            str(value.staff_approved_by_principal_id)
            if value.staff_approved_by_principal_id is not None
            else None
        ),
        "requested_at": value.requested_at.isoformat(),
        "starts_at": value.starts_at.isoformat() if value.starts_at is not None else None,
        "expires_at": value.expires_at.isoformat(),
        "incident_ref": value.incident_ref,
    }
