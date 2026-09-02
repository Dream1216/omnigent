"""Browser-safe production API for durable Preview child Runs.

The browser chooses only a completed source Run and the fixed static profile.
Runner IDs, Worktrees, fences, capabilities, lease tokens, commands, and
endpoint URLs are always derived by the server.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated, Literal, Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import HTTPConnection

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizationError, ProjectAuthorizer
from saas.control_plane.http_auth import SaasAuthProvider, SaasPrincipal
from saas.control_plane.preview_execution import (
    PreviewExecutionControlPlane,
    PreviewExecutionControlPlaneError,
    PreviewExecutionPolicy,
    PreviewExecutionState,
)
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver

IdempotencyKeyHeader = Annotated[
    str,
    Header(alias="Idempotency-Key", min_length=16, max_length=128),
]


class PreviewOpenBody(BaseModel):
    """The entire browser-supplied Preview selection surface."""

    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    preview_kind: Literal["static_web_v1"] = "static_web_v1"


class PreviewAuthProvider(Protocol):
    def get_principal(self, connection: HTTPConnection) -> SaasPrincipal | None: ...


class PreviewContextResolver(Protocol):
    def resolve_request_context(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        trace_id: str,
    ) -> RequestContext: ...


class PreviewProjectAuthorizer(Protocol):
    def bind_project_context(
        self,
        request: RequestContext,
        *,
        action: str,
        project_id: UUID,
    ) -> RequestContext: ...


class PreviewExecutionAuthority(Protocol):
    def request_preview(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        source_run_id: UUID,
        preview_kind: str,
        idempotency_key: str,
    ) -> PreviewExecutionState: ...

    def get_preview(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        preview_execution_id: UUID,
    ) -> PreviewExecutionState: ...

    def stop_preview(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        preview_execution_id: UUID,
        idempotency_key: str,
    ) -> PreviewExecutionState: ...


@dataclass(frozen=True, slots=True)
class ProductionPreviewControlPolicy:
    primary_origin: str
    preview_root_domain: str
    exchange_hmac_key: bytes
    lifetime: timedelta = timedelta(hours=1)

    def __post_init__(self) -> None:
        primary = urlsplit(self.primary_origin)
        if primary.scheme != "https" or primary.hostname is None:
            raise ValueError("Primary Preview control origin must use HTTPS")
        preview_root = self.preview_root_domain.lower().rstrip(".")
        primary_host = primary.hostname.lower().rstrip(".")
        if (
            preview_root == primary_host
            or preview_root.endswith(f".{primary_host}")
            or primary_host.endswith(f".{preview_root}")
        ):
            raise ValueError("Preview root must be cookie-isolated from the primary host")
        _ = self.execution_policy

    @property
    def execution_policy(self) -> PreviewExecutionPolicy:
        return PreviewExecutionPolicy(
            preview_root_domain=self.preview_root_domain,
            exchange_hmac_key=self.exchange_hmac_key,
            lifetime=self.lifetime,
        )

    @classmethod
    def from_origins(
        cls,
        *,
        primary_origin: str,
        preview_root_domain: str,
        lease_seconds: int,
        exchange_hmac_key: bytes,
    ) -> ProductionPreviewControlPolicy:
        return cls(
            primary_origin=primary_origin,
            preview_root_domain=preview_root_domain,
            exchange_hmac_key=exchange_hmac_key,
            lifetime=timedelta(seconds=lease_seconds),
        )


def _project_context(
    request: Request,
    *,
    tenant_id: UUID,
    space_id: UUID,
    project_id: UUID,
    auth_provider: PreviewAuthProvider,
    resolver: PreviewContextResolver,
    authorizer: PreviewProjectAuthorizer,
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
        if context.user_security_version != principal.session.security_version:
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "authorization_snapshot_stale",
                    "message": "session security version is stale",
                },
            )
        return authorizer.bind_project_context(
            context,
            action="preview.open",
            project_id=project_id,
        )
    except (ControlPlaneResolutionError, ProjectAuthorizationError) as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "preview_scope_unavailable", "message": "Preview is unavailable"},
        ) from error


def _response(state: PreviewExecutionState, response: Response) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.status_code = 200 if state.status == "ready" else 202
    payload: dict[str, object] = {
        "preview_id": str(state.preview_execution_id),
        "source_run_id": str(state.source_run_id),
        "status": state.status,
        "expires_at": state.expires_at.isoformat(),
        "replayed": state.replayed,
    }
    if state.exchange_url is not None:
        payload["url"] = state.exchange_url
    return payload


def _denied(error: PreviewExecutionControlPlaneError) -> HTTPException:
    status_code = (
        409
        if error.code
        in {
            "preview_already_active",
            "preview_idempotency_conflict",
            "preview_quota_exhausted",
        }
        else 404
    )
    return HTTPException(
        status_code=status_code,
        detail={"code": error.code, "message": "Preview is unavailable"},
    )


def create_production_preview_control_router(
    *,
    auth_provider: PreviewAuthProvider,
    resolver: PreviewContextResolver,
    authorizer: PreviewProjectAuthorizer,
    previews: PreviewExecutionAuthority,
) -> APIRouter:
    """Create authenticated child-Run create/status/stop routes."""

    router = APIRouter()
    base = "/tenants/{tenant_id}/spaces/{space_id}/projects/{project_id}/previews"

    @router.post(base, status_code=202)
    def open_preview(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        body: PreviewOpenBody,
        request: Request,
        response: Response,
        idempotency_key: IdempotencyKeyHeader,
    ) -> dict[str, object]:
        context = _project_context(
            request,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            auth_provider=auth_provider,
            resolver=resolver,
            authorizer=authorizer,
        )
        try:
            state = previews.request_preview(
                context,
                project_id=project_id,
                source_run_id=body.run_id,
                preview_kind=body.preview_kind,
                idempotency_key=idempotency_key,
            )
        except PreviewExecutionControlPlaneError as error:
            raise _denied(error) from error
        return _response(state, response)

    @router.get(f"{base}/{{preview_id}}")
    def preview_status(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        preview_id: UUID,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        context = _project_context(
            request,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            auth_provider=auth_provider,
            resolver=resolver,
            authorizer=authorizer,
        )
        try:
            state = previews.get_preview(
                context,
                project_id=project_id,
                preview_execution_id=preview_id,
            )
        except PreviewExecutionControlPlaneError as error:
            raise _denied(error) from error
        return _response(state, response)

    @router.delete(f"{base}/{{preview_id}}")
    def stop_preview(
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        preview_id: UUID,
        request: Request,
        response: Response,
        idempotency_key: IdempotencyKeyHeader,
    ) -> dict[str, object]:
        context = _project_context(
            request,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            auth_provider=auth_provider,
            resolver=resolver,
            authorizer=authorizer,
        )
        try:
            state = previews.stop_preview(
                context,
                project_id=project_id,
                preview_execution_id=preview_id,
                idempotency_key=idempotency_key,
            )
        except PreviewExecutionControlPlaneError as error:
            raise _denied(error) from error
        return _response(state, response)

    return router


def build_production_preview_control_router(
    *,
    auth_provider: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    sessions: sessionmaker[Session],
    policy: ProductionPreviewControlPolicy,
) -> APIRouter:
    """Compose the browser API over the app login and narrow P0S9 functions."""

    authorizer = ProjectAuthorizer(sessions)
    return create_production_preview_control_router(
        auth_provider=auth_provider,
        resolver=resolver,
        authorizer=authorizer,
        previews=PreviewExecutionControlPlane(
            sessions,
            policy=policy.execution_policy,
            authorizer=authorizer,
        ),
    )


__all__ = [
    "PreviewOpenBody",
    "ProductionPreviewControlPolicy",
    "build_production_preview_control_router",
    "create_production_preview_control_router",
]
