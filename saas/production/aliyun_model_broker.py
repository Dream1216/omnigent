"""Mint short-lived model bearers after live Host, session and SaaS admission."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from uuid import UUID

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as SqlAlchemyTimeoutError

from omnigent.db.db_models import current_workspace_id
from omnigent.errors import OmnigentError
from omnigent.server.auth import LEVEL_OWNER
from omnigent.server.permissions import check_session_access
from omnigent.stores import ConversationStore
from omnigent.stores.host_store import HostStore
from omnigent.stores.permission_store import PermissionStore
from saas.control_plane.context_snapshot import ControlPlaneDependencyUnavailable
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver
from saas.production.aliyun_model_lease import HostModelLeaseAuthority, HostModelLeaseError
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority

MODEL_TOKEN_TTL_S = 300


class HostModelAdmissionDenied(PermissionError):
    """A Host no longer owns the requested session or current SaaS scope."""


@dataclass(frozen=True)
class IssuedHostModelToken:
    token: str = field(repr=False)
    expires_at: int


class AliyunHostModelBroker:
    def __init__(
        self,
        *,
        leases: HostModelLeaseAuthority,
        resolver: SqlAlchemyContextResolver,
        host_store: HostStore,
        conversation_store: ConversationStore,
        permission_store: PermissionStore,
        authorities: Mapping[UUID, PlatformModelGatewayTokenAuthority],
        workspaces: Mapping[UUID, int],
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            not 1 <= len(authorities) <= 32
            or set(workspaces) != set(authorities)
            or len(set(workspaces.values())) != len(workspaces)
            or any(
                type(value) is not int or not 0 < value < 2**63 for value in workspaces.values()
            )
            or any(
                tenant.int == 0 or authority.tenant_id != tenant
                for tenant, authority in authorities.items()
            )
        ):
            raise ValueError("Host model authorities are invalid")
        self._leases = leases
        self._resolver = resolver
        self._hosts = host_store
        self._conversations = conversation_store
        self._permissions = permission_store
        self._authorities = MappingProxyType(dict(authorities))
        self._workspaces = MappingProxyType(dict(workspaces))
        self._clock = clock

    def issue(
        self, *, host_id: str, launch_token: str, lease_token: str, session_id: UUID
    ) -> IssuedHostModelToken:
        if not isinstance(session_id, UUID) or session_id.int == 0:
            raise HostModelAdmissionDenied("Host model session is invalid")
        lease = self._leases.verify(
            lease_token, host_id=host_id, launch_token=launch_token, now=int(self._clock())
        )
        workspace_id = current_workspace_id()
        if (
            type(workspace_id) is not int
            or workspace_id <= 0
            or (lease.runtime.physical_workspace_id != workspace_id)
            or self._workspaces.get(lease.runtime.tenant_id) != workspace_id
        ):
            raise HostModelAdmissionDenied("Host model workspace is invalid")
        host = self._hosts.resolve_launch_token(host_id, launch_token)
        if host is None or host.sandbox_provider != "e2b" or not host.sandbox_id:
            raise HostModelAdmissionDenied("Host model credential is unavailable")
        runtime = self._resolver.revalidate_host_model_scope(lease.runtime)
        if runtime.runtime_user_key != host.user_id:
            raise HostModelAdmissionDenied("Host model owner is invalid")
        session_key = session_id.hex
        conversation = self._conversations.get_conversation(session_key)
        if (
            conversation is None
            or conversation.host_id != host_id
            or not check_session_access(
                host.user_id,
                session_key,
                LEVEL_OWNER,
                self._permissions,
                self._conversations,
                conversation=conversation,
            )
        ):
            raise HostModelAdmissionDenied("Host model session is unavailable")
        self._hosts.admit_launch(host_id, session_key, host.user_id, host.account_generation)
        authority = self._authorities.get(runtime.tenant_id)
        now = int(self._clock())
        ttl = min(MODEL_TOKEN_TTL_S, lease.expires_at - now)
        if authority is None or ttl <= 0:
            raise HostModelAdmissionDenied("Host model authority is unavailable")
        return IssuedHostModelToken(
            authority.issue(session_id=session_id, ttl_seconds=ttl, now=now), now + ttl
        )


def create_aliyun_host_model_router(broker: AliyunHostModelBroker) -> APIRouter:
    """Mount only with the explicitly enabled Host-machine middleware route."""

    router = APIRouter()

    def error(status: int, code: str) -> JSONResponse:
        return JSONResponse(
            status_code=status,
            content={"error": {"code": code}},
            headers={"Cache-Control": "no-store"},
        )

    @router.post("/hosts/{host_id}/sessions/{session_id}/model-token", include_in_schema=False)
    async def model_token(
        host_id: str,
        session_id: UUID,
        x_omnigent_host_token: str | None = Header(default=None),
        x_omnigent_model_lease: str | None = Header(default=None),
    ) -> JSONResponse:
        if not x_omnigent_host_token or not x_omnigent_model_lease:
            return error(401, "aliyun_model_credential_required")
        try:
            issued = await asyncio.to_thread(
                broker.issue,
                host_id=host_id,
                session_id=session_id,
                launch_token=x_omnigent_host_token,
                lease_token=x_omnigent_model_lease,
            )
        except (
            HostModelAdmissionDenied,
            HostModelLeaseError,
            ControlPlaneResolutionError,
            OmnigentError,
        ):
            return error(403, "aliyun_model_admission_denied")
        except (ControlPlaneDependencyUnavailable, OperationalError, SqlAlchemyTimeoutError):
            return error(503, "aliyun_model_authority_unavailable")
        return JSONResponse(
            content={"token": issued.token, "expires_at": issued.expires_at},
            headers={"Cache-Control": "no-store"},
        )

    return router
