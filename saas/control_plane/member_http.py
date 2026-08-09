"""Action-level Tenant Members administration API for the shared SaaS console."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService
from saas.control_plane.member_admin import (
    MembershipInvitationView,
    TenantMemberAdministrationService,
    TenantMemberView,
)
from saas.control_plane.permissions import PERMISSION_CATALOG

MEMBER_ADMIN_ROUTE_PERMISSIONS = MappingProxyType(
    {
        "GET /tenants/{tenant}/members": "membership.read",
        "PUT /tenants/{tenant}/members/{user}/role": "membership.role.update",
        "POST /tenants/{tenant}/members/{user}/suspend": "membership.suspend",
        "POST /tenants/{tenant}/members/{user}/resume": "membership.suspend",
        "PUT /tenants/{tenant}/spaces/{space}/members/{user}/role": ("membership.role.update"),
        "POST /tenants/{tenant}/spaces/{space}/members/{user}/suspend": ("membership.suspend"),
        "POST /tenants/{tenant}/spaces/{space}/members/{user}/resume": ("membership.suspend"),
        "POST /tenants/{tenant}/membership-invitations": "membership.invite",
        "GET /tenants/{tenant}/membership-invitations": "membership.read",
        "POST /tenants/{tenant}/membership-invitations/{invitation}/reissue": (
            "membership.invite"
        ),
        "POST /tenants/{tenant}/membership-invitations/{invitation}/revoke": ("membership.invite"),
        "POST /tenants/{tenant}/ownership-transfers": "tenant.ownership.transfer",
        "POST /tenants/{tenant}/members/{user}/removal-preflights": "membership.remove",
        "POST /tenants/{tenant}/member-removal-preflights/{preflight}/execute": (
            "membership.remove"
        ),
    }
)


class InvitationCreateBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    tenant_role: Literal["admin", "billing_admin", "security_auditor", "operator", "member"] = (
        "member"
    )
    space_id: UUID | None = None
    space_role: Literal["admin", "operator", "member", "viewer"] | None = None
    ttl_hours: int = Field(default=168, ge=1, le=720)
    reason: str | None = Field(default=None, min_length=1, max_length=512)


class InvitationAcceptBody(BaseModel):
    token: str = Field(min_length=32, max_length=256)


class InvitationReissueBody(BaseModel):
    expected_version: int = Field(ge=1)
    ttl_hours: int = Field(default=168, ge=1, le=720)
    reason: str = Field(min_length=1, max_length=512)


class InvitationRevokeBody(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=512)


class TenantMemberRoleBody(BaseModel):
    role: Literal["admin", "billing_admin", "security_auditor", "operator", "member"]
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


class SpaceMemberRoleBody(BaseModel):
    role: Literal["admin", "operator", "member", "viewer"]
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


class MembershipStatusBody(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


def create_member_admin_router(
    *,
    auth_provider: SaasAuthProvider,
    lifecycle: MembershipLifecycleService,
    members: TenantMemberAdministrationService,
    invitation_acceptance: MembershipLifecycleService | None = None,
) -> APIRouter:
    """Create Tenant Members routes on the same authentication and service plane."""

    router = APIRouter()
    acceptance_lifecycle = invitation_acceptance or lifecycle

    @router.get("/tenants/{tenant_id}/members")
    def list_members(
        tenant_id: UUID,
        request: Request,
        response: Response,
        query: str | None = Query(default=None, max_length=128),
        status: str | None = Query(default=None, max_length=32),
        role: str | None = Query(default=None, max_length=32),
        after: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = members.list_members(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                query=query,
                status=status,
                role=role,
                after_id=after,
                limit=limit + 1,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return _page(values, limit, _member_payload, lambda value: value.user_id)

    @router.put("/tenants/{tenant_id}/members/{user_id}/role")
    def update_tenant_role(
        tenant_id: UUID,
        user_id: UUID,
        body: TenantMemberRoleBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            current = members.get_member(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            changed = lifecycle.update_tenant_membership(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                user_id=user_id,
                role=body.role,
                status=current.tenant_status,
                expected_version=body.expected_version,
                reason=body.reason,
                reauthenticated_at=principal.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        return _membership_changed_payload(changed)

    @router.post("/tenants/{tenant_id}/members/{user_id}/suspend")
    def suspend_tenant_member(
        tenant_id: UUID,
        user_id: UUID,
        body: MembershipStatusBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        return _change_tenant_status(
            auth_provider=auth_provider,
            lifecycle=lifecycle,
            members=members,
            tenant_id=tenant_id,
            user_id=user_id,
            status="suspended",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @router.post("/tenants/{tenant_id}/members/{user_id}/resume")
    def resume_tenant_member(
        tenant_id: UUID,
        user_id: UUID,
        body: MembershipStatusBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        return _change_tenant_status(
            auth_provider=auth_provider,
            lifecycle=lifecycle,
            members=members,
            tenant_id=tenant_id,
            user_id=user_id,
            status="active",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @router.put("/tenants/{tenant_id}/spaces/{space_id}/members/{user_id}/role")
    def update_space_role(
        tenant_id: UUID,
        space_id: UUID,
        user_id: UUID,
        body: SpaceMemberRoleBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            current = members.get_member(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            space = _space_access(current, space_id)
            changed = lifecycle.update_space_membership(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                space_id=space_id,
                user_id=user_id,
                role=body.role,
                status=space.status,
                expected_version=body.expected_version,
                reason=body.reason,
                reauthenticated_at=principal.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        return _membership_changed_payload(changed)

    @router.post("/tenants/{tenant_id}/spaces/{space_id}/members/{user_id}/suspend")
    def suspend_space_member(
        tenant_id: UUID,
        space_id: UUID,
        user_id: UUID,
        body: MembershipStatusBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        return _change_space_status(
            auth_provider=auth_provider,
            lifecycle=lifecycle,
            members=members,
            tenant_id=tenant_id,
            space_id=space_id,
            user_id=user_id,
            status="suspended",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @router.post("/tenants/{tenant_id}/spaces/{space_id}/members/{user_id}/resume")
    def resume_space_member(
        tenant_id: UUID,
        space_id: UUID,
        user_id: UUID,
        body: MembershipStatusBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        return _change_space_status(
            auth_provider=auth_provider,
            lifecycle=lifecycle,
            members=members,
            tenant_id=tenant_id,
            space_id=space_id,
            user_id=user_id,
            status="active",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @router.post("/tenants/{tenant_id}/membership-invitations", status_code=201)
    def create_invitation(
        tenant_id: UUID,
        body: InvitationCreateBody,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        now = datetime.now(timezone.utc)
        try:
            created = lifecycle.create_invitation(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                email=body.email,
                tenant_role=body.tenant_role,
                space_id=body.space_id,
                space_role=body.space_role,
                reason=body.reason,
                reauthenticated_at=principal.session.authenticated_at,
                expires_at=now + timedelta(hours=body.ttl_hours),
                idempotency_key=idempotency_key,
                now=now,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "invitation_id": str(created.invitation_id),
            "one_time_token": created.token,
            "replayed": created.replayed,
        }

    @router.get("/tenants/{tenant_id}/membership-invitations")
    def list_invitations(
        tenant_id: UUID,
        request: Request,
        response: Response,
        query: str | None = Query(default=None, max_length=128),
        status: str | None = Query(default=None, max_length=32),
        after: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = members.list_invitations(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                query=query,
                status=status,
                after_id=after,
                limit=limit + 1,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return _page(
            values,
            limit,
            _invitation_payload,
            lambda value: value.invitation_id,
        )

    @router.post("/tenants/{tenant_id}/membership-invitations/{invitation_id}/reissue")
    def reissue_invitation(
        tenant_id: UUID,
        invitation_id: UUID,
        body: InvitationReissueBody,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        now = datetime.now(timezone.utc)
        try:
            changed = members.reissue_invitation(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                invitation_id=invitation_id,
                expected_version=body.expected_version,
                expires_at=now + timedelta(hours=body.ttl_hours),
                reason=body.reason,
                idempotency_key=idempotency_key,
                now=now,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "invitation_id": str(changed.invitation_id),
            "one_time_token": changed.token,
            "version": changed.version,
            "expires_at": changed.expires_at.isoformat(),
            "replayed": changed.replayed,
        }

    @router.post("/tenants/{tenant_id}/membership-invitations/{invitation_id}/revoke")
    def revoke_invitation(
        tenant_id: UUID,
        invitation_id: UUID,
        body: InvitationRevokeBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            changed = members.revoke_invitation(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                invitation_id=invitation_id,
                expected_version=body.expected_version,
                reason=body.reason,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        return {
            "invitation_id": str(changed.invitation_id),
            "version": changed.version,
            "replayed": changed.replayed,
        }

    @router.post("/membership-invitations/accept")
    def accept_invitation(
        body: InvitationAcceptBody,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            accepted = acceptance_lifecycle.accept_invitation(
                actor_id=principal.session.user_id,
                token=body.token,
            )
        except LifecycleError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "tenant_id": str(accepted.tenant_id),
            "space_id": str(accepted.space_id) if accepted.space_id else None,
            "tenant_membership_version": accepted.tenant_membership_version,
            "space_membership_version": accepted.space_membership_version,
            "replayed": accepted.replayed,
        }

    return router


def _change_tenant_status(
    *,
    auth_provider: SaasAuthProvider,
    lifecycle: MembershipLifecycleService,
    members: TenantMemberAdministrationService,
    tenant_id: UUID,
    user_id: UUID,
    status: Literal["active", "suspended"],
    body: MembershipStatusBody,
    request: Request,
    idempotency_key: str,
) -> dict[str, object]:
    principal = _principal(auth_provider, request)
    try:
        current = members.get_member(
            actor_id=principal.session.user_id,
            tenant_id=tenant_id,
            user_id=user_id,
        )
        changed = lifecycle.update_tenant_membership(
            actor_id=principal.session.user_id,
            tenant_id=tenant_id,
            user_id=user_id,
            role=current.tenant_role,
            status=status,
            expected_version=body.expected_version,
            reason=body.reason,
            reauthenticated_at=principal.session.authenticated_at,
            idempotency_key=idempotency_key,
        )
    except LifecycleError as error:
        raise _http_error(error) from error
    return _membership_changed_payload(changed)


def _change_space_status(
    *,
    auth_provider: SaasAuthProvider,
    lifecycle: MembershipLifecycleService,
    members: TenantMemberAdministrationService,
    tenant_id: UUID,
    space_id: UUID,
    user_id: UUID,
    status: Literal["active", "suspended"],
    body: MembershipStatusBody,
    request: Request,
    idempotency_key: str,
) -> dict[str, object]:
    principal = _principal(auth_provider, request)
    try:
        current = members.get_member(
            actor_id=principal.session.user_id,
            tenant_id=tenant_id,
            user_id=user_id,
        )
        space = _space_access(current, space_id)
        changed = lifecycle.update_space_membership(
            actor_id=principal.session.user_id,
            tenant_id=tenant_id,
            space_id=space_id,
            user_id=user_id,
            role=space.role,
            status=status,
            expected_version=body.expected_version,
            reason=body.reason,
            reauthenticated_at=principal.session.authenticated_at,
            idempotency_key=idempotency_key,
        )
    except LifecycleError as error:
        raise _http_error(error) from error
    return _membership_changed_payload(changed)


def _space_access(member: TenantMemberView, space_id: UUID):
    for value in member.space_access:
        if value.space_id == space_id:
            return value
    raise LifecycleError("membership_not_found", "Space membership does not exist")


def _principal(auth_provider: SaasAuthProvider, request: Request):
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "authentication_required", "message": "login required"},
        )
    return principal


def _page(values, limit: int, payload, identifier) -> dict[str, object]:
    selected = values[:limit]
    has_more = len(values) > limit
    return {
        "items": [payload(value) for value in selected],
        "next_cursor": str(identifier(selected[-1])) if selected and has_more else None,
    }


def _member_payload(value: TenantMemberView) -> dict[str, object]:
    return {
        "user_id": str(value.user_id),
        "display_name": value.display_name,
        "primary_email_normalized": value.primary_email_normalized,
        "user_status": value.user_status,
        "tenant_role": value.tenant_role,
        "tenant_status": value.tenant_status,
        "tenant_membership_version": value.tenant_membership_version,
        "joined_at": value.joined_at.isoformat() if value.joined_at else None,
        "login_methods": [
            {
                "provider": method.provider,
                "status": method.status,
                "email_verified": method.email_verified,
            }
            for method in value.login_methods
        ],
        "space_access": [
            {
                "space_id": str(access.space_id),
                "space_name": access.space_name,
                "role": access.role,
                "status": access.status,
                "version": access.version,
            }
            for access in value.space_access
        ],
    }


def _invitation_payload(value: MembershipInvitationView) -> dict[str, object]:
    return {
        "invitation_id": str(value.invitation_id),
        "email_normalized": value.email_normalized,
        "tenant_role": value.tenant_role,
        "space_id": str(value.space_id) if value.space_id else None,
        "space_name": value.space_name,
        "space_role": value.space_role,
        "status": value.status,
        "version": value.version,
        "expires_at": value.expires_at.isoformat(),
        "created_by": str(value.created_by),
        "accepted_by": str(value.accepted_by) if value.accepted_by else None,
        "created_at": value.created_at.isoformat(),
    }


def _membership_changed_payload(changed) -> dict[str, object]:
    return {
        "scope": changed.scope,
        "membership_version": changed.membership_version,
        "security_version": changed.security_version,
        "revoked_session_count": changed.revoked_session_count,
        "replayed": changed.replayed,
    }


def _http_error(error: LifecycleError) -> HTTPException:
    if error.code == "forbidden":
        status = 403
    elif error.code.endswith("_not_found") or error.code == "membership_not_found":
        status = 404
    else:
        status = 409
    return HTTPException(
        status_code=status,
        detail={"code": error.code, "message": str(error)},
    )


def validate_member_admin_route_permissions() -> None:
    """Fail CI when the Tenant Members surface drifts from the catalog."""

    unknown = set(MEMBER_ADMIN_ROUTE_PERMISSIONS.values()) - set(PERMISSION_CATALOG)
    if unknown:
        raise RuntimeError(f"Tenant Members routes reference unknown permissions: {unknown}")


validate_member_admin_route_permissions()
