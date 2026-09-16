"""Shared SaaS authority used by the modern and compatibility delivery routes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizationError, ProjectAuthorizer
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver
from saas.delivery.client import DcpResponseError, DeliveryClient, DeliveryProject


@dataclass
class DeliveryAccess:
    auth: SaasAuthProvider
    resolver: SqlAlchemyContextResolver
    sessions: sessionmaker[Session]
    client: DeliveryClient | None

    @property
    def authorizer(self) -> ProjectAuthorizer:
        return ProjectAuthorizer(self.sessions)

    def binding(self, project_id: UUID) -> DeliveryProject:
        if self.client is None:
            raise HTTPException(503, detail={"code": "delivery_not_configured"})
        project = next(
            (p for p in self.client.config.projects if p.project_id == project_id), None
        )
        if project is None:
            raise HTTPException(404, detail={"code": "delivery_scope_unavailable"})
        return project

    def context(self, request: Request, project: DeliveryProject, *actions: str) -> RequestContext:
        principal = self.auth.get_principal(request)
        if principal is None:
            raise HTTPException(401, detail={"code": "authentication_required"})
        try:
            current = self.resolver.resolve_request_context(
                actor_id=principal.session.user_id,
                tenant_id=project.tenant_id,
                space_id=project.space_id,
                trace_id=uuid4().hex,
            )
            if current.user_security_version != principal.session.security_version:
                raise HTTPException(401, detail={"code": "authorization_snapshot_stale"})
            for action in ("project.content.read", *actions):
                current = self.authorizer.bind_project_context(
                    current, action=action, project_id=project.project_id
                )
            return current
        except (ControlPlaneResolutionError, ProjectAuthorizationError) as error:
            raise HTTPException(404, detail={"code": "delivery_scope_unavailable"}) from error

    async def call(
        self,
        current: RequestContext,
        permissions: frozenset[str],
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        key: str | None = None,
    ) -> Any:
        assert self.client is not None
        try:
            return await self.client.request(
                current, permissions, method, path, body=body, key=key
            )
        except DcpResponseError as error:
            raise HTTPException(
                error.status, detail={"code": error.code, "retryable": error.retryable}
            ) from error
