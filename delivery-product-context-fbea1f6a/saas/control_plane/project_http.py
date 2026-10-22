"""Action-level HTTP API for Project Admin, access explanation, and Bindings."""

from __future__ import annotations

from datetime import datetime
from importlib.resources import files
from types import MappingProxyType
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.responses import HTMLResponse, Response

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizationError, ProjectAuthorizer
from saas.control_plane.bindings import RuntimeBindingService
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import PERMISSION_CATALOG, permission_catalog_payload
from saas.control_plane.projects import ProjectAdministrationService, ProjectMetadata
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver

PROJECT_ADMIN_ROUTE_PERMISSIONS = MappingProxyType(
    {
        "POST /tenants/{tenant}/spaces/{space}/projects": "project.create",
        "GET /tenants/{tenant}/spaces/{space}/projects": "project.read_metadata",
        "GET /tenants/{tenant}/spaces/{space}/projects/{project}": "project.read_metadata",
        "PATCH /tenants/{tenant}/spaces/{space}/projects/{project}/visibility": ("project.update"),
        "PUT /tenants/{tenant}/spaces/{space}/projects/{project}/members/{subject}": (
            "grant.manage"
        ),
        "DELETE /tenants/{tenant}/spaces/{space}/projects/{project}/members/{subject}": (
            "grant.manage"
        ),
        "PUT /tenants/{tenant}/spaces/{space}/projects/{project}/resource-grants": (
            "grant.manage"
        ),
        "DELETE /tenants/{tenant}/spaces/{space}/projects/{project}/resource-grants/{grant}": (
            "grant.manage"
        ),
        "POST /tenants/{tenant}/spaces/{space}/projects/{project}/access/decisions": (
            "role.preview"
        ),
        "POST /tenants/{tenant}/spaces/{space}/projects/{project}/bindings": (
            "runtime.binding.manage"
        ),
        "POST /tenants/{tenant}/spaces/{space}/bindings/{binding}/retire": (
            "runtime.binding.manage"
        ),
    }
)


class ProjectCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    visibility: Literal["private", "space", "restricted"] = "private"


class ProjectVisibilityBody(BaseModel):
    visibility: Literal["private", "space", "restricted"]
    expected_authorization_version: int = Field(ge=1)


class ProjectMembershipBody(BaseModel):
    role: Literal["owner", "manage", "operate", "edit", "read"]
    expires_at: datetime | None = None


class ResourceGrantBody(BaseModel):
    resource_type: str = Field(min_length=1, max_length=64)
    resource_id: UUID
    subject_type: Literal["user", "space"]
    subject_id: UUID
    role: Literal["owner", "manage", "operate", "edit", "read"]
    expires_at: datetime | None = None


class AccessDecisionBody(BaseModel):
    action: str = Field(min_length=1, max_length=128)
    subject_user_id: UUID | None = None
    resource_type: str | None = Field(default=None, min_length=1, max_length=64)
    resource_id: UUID | None = None


class RuntimeBindingBody(BaseModel):
    runtime_partition_id: UUID
    resource_type: str = Field(min_length=1, max_length=64)
    runtime_resource_id: str = Field(min_length=1, max_length=256)
    saas_resource_id: UUID
    expected_partition_generation: int = Field(ge=1)


class RetireBindingBody(BaseModel):
    expected_binding_generation: int = Field(ge=1)


def _project_payload(project: ProjectMetadata) -> dict[str, object]:
    return {
        "project_id": str(project.project_id),
        "tenant_id": str(project.tenant_id),
        "space_id": str(project.space_id),
        "name": project.name,
        "visibility": project.visibility,
        "status": project.status,
        "authorization_version": project.authorization_version,
    }


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


def create_project_admin_router(
    *,
    auth_provider: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    projects: ProjectAdministrationService,
    authorizer: ProjectAuthorizer,
    bindings: RuntimeBindingService | None = None,
) -> APIRouter:
    """Create Project Admin routes; every mutating route has a stable permission."""

    router = APIRouter()

    @router.get("/admin/projects", include_in_schema=False)
    def project_admin_ui() -> HTMLResponse:
        return HTMLResponse(
            files("saas.admin_ui").joinpath("project_admin.html").read_text(encoding="utf-8"),
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
                    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.get("/admin/assets/project-admin.css", include_in_schema=False)
    def project_admin_css() -> Response:
        return _admin_asset("project_admin.css", "text/css")

    @router.get("/admin/assets/project-admin.js", include_in_schema=False)
    def project_admin_javascript() -> Response:
        return _admin_asset("project_admin.js", "text/javascript")

    @router.get("/admin/permissions")
    def permission_catalog(request: Request) -> dict[str, object]:
        if auth_provider.get_principal(request) is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "authentication_required", "message": "login required"},
            )
        return permission_catalog_payload()

    @router.post("/tenants/{tenant_id}/spaces/{space_id}/projects", status_code=201)
    def create_project(
        tenant_id: UUID,
        space_id: UUID,
        body: ProjectCreateBody,
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
            created = projects.create_project(
                context,
                name=body.name,
                visibility=body.visibility,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, 409) from error
        return {
            "project_id": str(created.project_id),
            "authorization_version": created.authorization_version,
            "replayed": created.replayed,
        }

    @router.get("/tenants/{tenant_id}/spaces/{space_id}/projects")
    def list_projects(
        tenant_id: UUID, space_id: UUID, request: Request
    ) -> list[dict[str, object]]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        return [_project_payload(project) for project in projects.list_project_metadata(context)]

    @router.get("/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}")
    def get_project(
        tenant_id: UUID, space_id: UUID, project_id: UUID, request: Request
    ) -> dict[str, object]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        try:
            project = projects.get_project_metadata(context, project_id=project_id)
        except (LifecycleError, ProjectAuthorizationError) as error:
            raise _http_error(error, 404) from error
        return _project_payload(project)

    @router.patch("/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/visibility")
    def update_visibility(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        body: ProjectVisibilityBody,
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
            changed = projects.update_visibility(
                context,
                project_id=project_id,
                visibility=body.visibility,
                expected_authorization_version=body.expected_authorization_version,
                idempotency_key=idempotency_key,
            )
        except (LifecycleError, ProjectAuthorizationError) as error:
            raise _http_error(error, 409) from error
        return {
            "project_id": str(changed.project_id),
            "authorization_version": changed.authorization_version,
            "replayed": changed.replayed,
        }

    @router.put(
        "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/"
        "members/{subject_type}/{subject_id}"
    )
    def set_project_membership(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        subject_type: Literal["user", "space"],
        subject_id: UUID,
        body: ProjectMembershipBody,
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
            changed = projects.set_project_membership(
                context,
                project_id=project_id,
                subject_type=subject_type,
                subject_id=subject_id,
                role=body.role,
                expires_at=body.expires_at,
                idempotency_key=idempotency_key,
            )
        except (LifecycleError, ProjectAuthorizationError) as error:
            raise _http_error(error, 409) from error
        return _grant_payload(changed)

    @router.delete(
        "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/"
        "members/{subject_type}/{subject_id}"
    )
    def revoke_project_membership(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        subject_type: Literal["user", "space"],
        subject_id: UUID,
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
            changed = projects.revoke_project_membership(
                context,
                project_id=project_id,
                subject_type=subject_type,
                subject_id=subject_id,
                idempotency_key=idempotency_key,
            )
        except (LifecycleError, ProjectAuthorizationError) as error:
            raise _http_error(error, 409) from error
        return _grant_payload(changed)

    @router.put("/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/resource-grants")
    def set_resource_grant(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        body: ResourceGrantBody,
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
            changed = projects.set_resource_grant(
                context,
                project_id=project_id,
                resource_type=body.resource_type,
                resource_id=body.resource_id,
                subject_type=body.subject_type,
                subject_id=body.subject_id,
                role=body.role,
                expires_at=body.expires_at,
                idempotency_key=idempotency_key,
            )
        except (LifecycleError, ProjectAuthorizationError) as error:
            raise _http_error(error, 409) from error
        return _grant_payload(changed)

    @router.delete(
        "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/resource-grants/{grant_id}"
    )
    def revoke_resource_grant(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        grant_id: UUID,
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
            changed = projects.revoke_resource_grant(
                context,
                project_id=project_id,
                grant_id=grant_id,
                idempotency_key=idempotency_key,
            )
        except (LifecycleError, ProjectAuthorizationError) as error:
            raise _http_error(error, 409) from error
        return _grant_payload(changed)

    @router.post("/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/access/decisions")
    def explain_access(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        body: AccessDecisionBody,
        request: Request,
    ) -> dict[str, object]:
        context = _context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
            space_id=space_id,
        )
        try:
            authorizer.require(context, action="role.preview", project_id=project_id)
            subject_context = context
            if body.subject_user_id is not None and body.subject_user_id != context.actor_id:
                subject_context = resolver.resolve_request_context(
                    actor_id=body.subject_user_id,
                    tenant_id=tenant_id,
                    space_id=space_id,
                    trace_id=f"{context.trace_id}:simulation",
                )
            decision = authorizer.evaluate(
                subject_context,
                action=body.action,
                project_id=project_id,
                resource_type=body.resource_type,
                resource_id=body.resource_id,
                mode="shadow",
            )
        except (ControlPlaneResolutionError, ProjectAuthorizationError) as error:
            raise _http_error(error, 404) from error
        return {
            "decision_id": str(decision.decision_id),
            "allowed": decision.allowed,
            "reason": decision.reason,
            "action": decision.action,
            "project_id": str(decision.project_id),
            "subject_user_id": str(subject_context.actor_id),
            "project_authorization_version": decision.project_authorization_version,
            "policy_version": decision.policy_version,
            "mode": decision.mode,
            "sources": [source.payload() for source in decision.sources],
        }

    if bindings is not None:

        @router.post(
            "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/bindings",
            status_code=201,
        )
        def bind_resource(
            tenant_id: UUID,
            space_id: UUID,
            project_id: UUID,
            body: RuntimeBindingBody,
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
                changed = bindings.bind_resource(
                    context,
                    project_id=project_id,
                    runtime_partition_id=body.runtime_partition_id,
                    resource_type=body.resource_type,
                    runtime_resource_id=body.runtime_resource_id,
                    saas_resource_id=body.saas_resource_id,
                    expected_partition_generation=body.expected_partition_generation,
                    idempotency_key=idempotency_key,
                )
            except (LifecycleError, ProjectAuthorizationError) as error:
                raise _http_error(error, 409) from error
            return _binding_payload(changed)

        @router.post("/tenants/{tenant_id}/spaces/{space_id}/bindings/{binding_id}/retire")
        def retire_binding(
            tenant_id: UUID,
            space_id: UUID,
            binding_id: UUID,
            body: RetireBindingBody,
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
                changed = bindings.retire_binding(
                    context,
                    binding_id=binding_id,
                    expected_binding_generation=body.expected_binding_generation,
                    idempotency_key=idempotency_key,
                )
            except (LifecycleError, ProjectAuthorizationError) as error:
                raise _http_error(error, 409) from error
            return _binding_payload(changed)

    return router


def _grant_payload(changed: object) -> dict[str, object]:
    from saas.control_plane.projects import ScopedGrantChanged

    if not isinstance(changed, ScopedGrantChanged):
        raise TypeError("expected ScopedGrantChanged")
    return {
        "project_id": str(changed.project_id),
        "grant_id": str(changed.grant_id) if changed.grant_id else None,
        "subject_type": changed.subject_type,
        "subject_id": str(changed.subject_id),
        "role": changed.role,
        "status": changed.status,
        "authorization_version": changed.authorization_version,
        "replayed": changed.replayed,
    }


def _binding_payload(changed: object) -> dict[str, object]:
    from saas.control_plane.bindings import RuntimeBindingChanged

    if not isinstance(changed, RuntimeBindingChanged):
        raise TypeError("expected RuntimeBindingChanged")
    return {
        "binding_id": str(changed.binding_id),
        "binding_generation": changed.binding_generation,
        "status": changed.status,
        "replayed": changed.replayed,
    }


def _http_error(
    error: LifecycleError | ProjectAuthorizationError | ControlPlaneResolutionError,
    status_code: int,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": error.code, "message": str(error)},
    )


def _admin_asset(name: str, media_type: str) -> Response:
    return Response(
        files("saas.admin_ui").joinpath(name).read_bytes(),
        media_type=media_type,
        headers={
            "Cache-Control": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


def validate_project_admin_route_permissions() -> None:
    """Fail CI when an action route references an unregistered permission."""

    unknown = set(PROJECT_ADMIN_ROUTE_PERMISSIONS.values()) - set(PERMISSION_CATALOG)
    if unknown:
        raise RuntimeError(f"Project Admin routes reference unknown permissions: {unknown}")


validate_project_admin_route_permissions()
