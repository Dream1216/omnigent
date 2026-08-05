"""Action-level Admin API for Tenant groups and project custom roles."""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime
from types import MappingProxyType
from typing import TypeVar
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from saas.compatibility import RequestContext
from saas.control_plane.enterprise_access import (
    EnterpriseAccessService,
    EnterpriseCustomRoleView,
    EnterpriseGroupRoleAssignmentView,
    EnterpriseGroupView,
)
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import PERMISSION_CATALOG
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver

ENTERPRISE_ADMIN_ROUTE_PERMISSIONS = MappingProxyType(
    {
        "POST /tenants/{tenant}/groups": "group.manage",
        "GET /tenants/{tenant}/groups": "group.read",
        "PUT /tenants/{tenant}/groups/{group}/members/{user}": "group.manage",
        "DELETE /tenants/{tenant}/groups/{group}/members/{user}": "group.manage",
        "POST /tenants/{tenant}/spaces/{space}/projects/{project}/custom-roles": (
            "custom_role.manage"
        ),
        "GET /tenants/{tenant}/spaces/{space}/projects/{project}/custom-roles": (
            "custom_role.read"
        ),
        "PUT /tenants/{tenant}/spaces/{space}/projects/{project}/custom-roles/{role}": (
            "custom_role.manage"
        ),
        "POST /tenants/{tenant}/spaces/{space}/projects/{project}/group-role-assignments": (
            "custom_role.manage"
        ),
        "DELETE /tenants/{tenant}/spaces/{space}/projects/{project}/"
        "group-role-assignments/{assignment}": "custom_role.manage",
    }
)


class GroupCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)


class GroupMembershipBody(BaseModel):
    expires_at: datetime | None = None


class GroupMembershipRemoveBody(BaseModel):
    expected_version: int = Field(ge=1)


class CustomRoleBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    permissions: list[str] = Field(min_length=1, max_length=64)


class CustomRoleUpdateBody(CustomRoleBody):
    expected_version: int = Field(ge=1)


class GroupRoleAssignmentBody(BaseModel):
    group_id: UUID
    custom_role_id: UUID
    expires_at: datetime | None = None


class GroupRoleAssignmentRemoveBody(BaseModel):
    expected_version: int = Field(ge=1)


_Item = TypeVar("_Item")


def _context(
    request: Request,
    *,
    auth_provider: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    tenant_id: UUID,
    space_id: UUID,
) -> RequestContext:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "authentication_required", "message": "login required"},
        )
    try:
        context = resolver.resolve_request_context(
            actor_id=principal.session.user_id,
            tenant_id=tenant_id,
            space_id=space_id,
            trace_id=request.headers.get("x-request-id") or uuid4().hex,
        )
    except ControlPlaneResolutionError as error:
        raise _http_error(error, 404) from error
    if context.user_security_version != principal.session.security_version:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "authorization_snapshot_stale",
                "message": "session security version is stale",
            },
        )
    return context


def _tenant_context(
    request: Request,
    *,
    auth_provider: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    tenant_id: UUID,
) -> RequestContext:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "authentication_required", "message": "login required"},
        )
    try:
        scopes = resolver.list_available_scopes(actor_id=principal.session.user_id)
    except ControlPlaneResolutionError as error:
        raise _http_error(error, 404) from error
    space = next((scope for scope in scopes if scope.tenant_id == tenant_id), None)
    if space is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "scope_not_authorized", "message": "scope is not accessible"},
        )
    return _context(
        request,
        auth_provider=auth_provider,
        resolver=resolver,
        tenant_id=tenant_id,
        space_id=space.space_id,
    )


def _http_error(error: Exception, status: int) -> HTTPException:
    return HTTPException(
        status_code=status,
        detail={
            "code": getattr(error, "code", "enterprise_access_failed"),
            "message": str(error),
        },
    )


def _status(error: LifecycleError) -> int:
    if error.code in {
        "group_manage_forbidden",
        "group_read_forbidden",
        "permission_not_granted",
        "scope_not_authorized",
    }:
        return 403
    if error.code in {"group_not_active", "custom_role_not_active", "project_not_active"}:
        return 404
    if error.code.endswith("_invalid") or error.code == "custom_role_permission_not_allowed":
        return 422
    return 409


def _encode_cursor(value: UUID) -> str:
    return base64.urlsafe_b64encode(value.bytes).decode().rstrip("=")


def _decode_cursor(value: str | None) -> UUID | None:
    if value is None:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return UUID(bytes=raw)
    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=400,
            detail={"code": "cursor_invalid", "message": "cursor is invalid"},
        ) from error


def _page(
    values: tuple[_Item, ...],
    *,
    limit: int,
    identifier: Callable[[_Item], UUID],
    payload: Callable[[_Item], dict[str, object]],
) -> dict[str, object]:
    selected = values[:limit]
    has_more = len(values) > limit
    return {
        "items": [payload(value) for value in selected],
        "next_cursor": _encode_cursor(identifier(selected[-1])) if selected and has_more else None,
    }


def _group_payload(value: EnterpriseGroupView) -> dict[str, object]:
    return {
        "id": str(value.id),
        "tenant_id": str(value.tenant_id),
        "name": value.name,
        "description": value.description,
        "status": value.status,
        "version": value.version,
        "replayed": value.replayed,
    }


def _role_payload(value: EnterpriseCustomRoleView) -> dict[str, object]:
    return {
        "id": str(value.id),
        "tenant_id": str(value.tenant_id),
        "space_id": str(value.space_id),
        "project_id": str(value.project_id),
        "name": value.name,
        "description": value.description,
        "permissions": list(value.permissions),
        "status": value.status,
        "version": value.version,
        "authorization_version": value.authorization_version,
        "replayed": value.replayed,
    }


def _assignment_payload(value: EnterpriseGroupRoleAssignmentView) -> dict[str, object]:
    return {
        "id": str(value.id),
        "tenant_id": str(value.tenant_id),
        "space_id": str(value.space_id),
        "project_id": str(value.project_id),
        "group_id": str(value.group_id),
        "custom_role_id": str(value.custom_role_id),
        "status": value.status,
        "expires_at": value.expires_at.isoformat() if value.expires_at else None,
        "version": value.version,
        "authorization_version": value.authorization_version,
        "replayed": value.replayed,
    }


def create_enterprise_admin_router(
    *,
    auth_provider: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    enterprise_access: EnterpriseAccessService,
) -> APIRouter:
    """Create Cookie-only enterprise governance routes under the SaaS admin origin."""

    router = APIRouter()

    @router.post("/tenants/{tenant_id}/groups", status_code=201)
    def create_group(
        tenant_id: UUID,
        body: GroupCreateBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context = _tenant_context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
        )
        try:
            return _group_payload(
                enterprise_access.create_group(
                    context,
                    name=body.name,
                    description=body.description,
                    idempotency_key=idempotency_key,
                )
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error

    @router.get("/tenants/{tenant_id}/groups")
    def list_groups(
        tenant_id: UUID,
        request: Request,
        cursor: str | None = Query(default=None, max_length=128),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        context = _tenant_context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
        )
        try:
            values = enterprise_access.list_groups(
                context,
                after_id=_decode_cursor(cursor),
                limit=limit + 1,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return _page(
            values,
            limit=limit,
            identifier=lambda value: value.id,
            payload=_group_payload,
        )

    @router.put("/tenants/{tenant_id}/groups/{group_id}/members/{user_id}")
    def add_group_member(
        tenant_id: UUID,
        group_id: UUID,
        user_id: UUID,
        body: GroupMembershipBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context = _tenant_context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
        )
        try:
            changed = enterprise_access.add_group_member(
                context,
                group_id=group_id,
                user_id=user_id,
                expires_at=body.expires_at,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return {
            "group_id": str(changed.group_id),
            "user_id": str(changed.user_id),
            "status": changed.status,
            "expires_at": changed.expires_at.isoformat() if changed.expires_at else None,
            "version": changed.version,
            "replayed": changed.replayed,
        }

    @router.delete("/tenants/{tenant_id}/groups/{group_id}/members/{user_id}")
    def remove_group_member(
        tenant_id: UUID,
        group_id: UUID,
        user_id: UUID,
        body: GroupMembershipRemoveBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context = _tenant_context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
        )
        try:
            changed = enterprise_access.remove_group_member(
                context,
                group_id=group_id,
                user_id=user_id,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return {
            "group_id": str(changed.group_id),
            "user_id": str(changed.user_id),
            "status": changed.status,
            "version": changed.version,
            "security_version": changed.security_version,
            "revoked_session_count": changed.revoked_session_count,
            "replayed": changed.replayed,
        }

    @router.post(
        "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/custom-roles",
        status_code=201,
    )
    def create_custom_role(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        body: CustomRoleBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        try:
            value = enterprise_access.create_custom_role(
                context,
                project_id=project_id,
                name=body.name,
                description=body.description,
                permissions=body.permissions,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return _role_payload(value)

    @router.get("/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/custom-roles")
    def list_custom_roles(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        request: Request,
        cursor: str | None = Query(default=None, max_length=128),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        try:
            values = enterprise_access.list_custom_roles(
                context,
                project_id=project_id,
                after_id=_decode_cursor(cursor),
                limit=limit + 1,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return _page(
            values,
            limit=limit,
            identifier=lambda value: value.id,
            payload=_role_payload,
        )

    @router.put(
        "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/"
        "custom-roles/{custom_role_id}"
    )
    def update_custom_role(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        custom_role_id: UUID,
        body: CustomRoleUpdateBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        try:
            value = enterprise_access.update_custom_role(
                context,
                project_id=project_id,
                custom_role_id=custom_role_id,
                name=body.name,
                description=body.description,
                permissions=body.permissions,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return _role_payload(value)

    @router.post(
        "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/group-role-assignments",
        status_code=201,
    )
    def assign_group_role(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        body: GroupRoleAssignmentBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        try:
            value = enterprise_access.assign_group_role(
                context,
                project_id=project_id,
                group_id=body.group_id,
                custom_role_id=body.custom_role_id,
                expires_at=body.expires_at,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return _assignment_payload(value)

    @router.delete(
        "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/"
        "group-role-assignments/{assignment_id}"
    )
    def revoke_group_role(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        assignment_id: UUID,
        body: GroupRoleAssignmentRemoveBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        try:
            value = enterprise_access.revoke_group_role(
                context,
                project_id=project_id,
                assignment_id=assignment_id,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, _status(error)) from error
        return _assignment_payload(value)

    return router


def validate_enterprise_admin_route_permissions() -> None:
    unknown = set(ENTERPRISE_ADMIN_ROUTE_PERMISSIONS.values()) - set(PERMISSION_CATALOG)
    if unknown:
        raise RuntimeError(f"Enterprise Admin routes reference unknown permissions: {unknown}")


validate_enterprise_admin_route_permissions()
