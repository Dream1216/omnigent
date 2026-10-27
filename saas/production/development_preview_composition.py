"""Bind development previews to live SaaS sessions and official runtime ownership."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import sqlalchemy as sa
from fastapi import HTTPException

from omnigent.server.auth import LEVEL_OWNER
from omnigent.server.routes._auth_helpers import require_access_and_level
from omnigent.server.routes._sessions.helpers import _get_runner_client_for_resource_access
from saas.compatibility import RuntimeResolutionError, bind_runtime_context
from saas.control_plane.db_models import AuthSessionRecord, GlobalUser
from saas.control_plane.development_preview import (
    DevelopmentPreviewGrants,
    DevelopmentPreviewScope,
)
from saas.control_plane.resolver import ControlPlaneResolutionError
from saas.production.development_preview import (
    DevelopmentPreviewBroker,
    DevelopmentPreviewHostMiddleware,
)


def install_development_previews(app, *, config, sessions, official, integration) -> None:
    root = config.development_preview_root_domain
    key = config.secrets.development_preview_key
    if root is None and key is None:
        return
    if not root or key is None:
        raise ValueError("Development preview requires a domain and signing key")
    grants = DevelopmentPreviewGrants(sessions.app, key)

    def current_runtime(scope: DevelopmentPreviewScope):
        now = datetime.now(timezone.utc)
        with sessions.authenticator() as db:
            active = db.scalar(
                sa.select(AuthSessionRecord.id)
                .join(GlobalUser, GlobalUser.id == AuthSessionRecord.user_id)
                .where(
                    AuthSessionRecord.id == scope.auth_session_id,
                    AuthSessionRecord.user_id == scope.actor_id,
                    AuthSessionRecord.security_version == scope.security_version,
                    AuthSessionRecord.expires_at > now,
                    AuthSessionRecord.revoked_at.is_(None),
                    GlobalUser.status == "active",
                    GlobalUser.security_version == scope.security_version,
                )
            )
            if active is None:
                raise HTTPException(403)
        resolver = integration.context_resolver
        context = resolver.resolve_request_context(
            actor_id=scope.actor_id,
            tenant_id=scope.tenant_id,
            space_id=scope.space_id,
            trace_id=f"dev-preview-{uuid4().hex}",
        )
        runtime = resolver.resolve_space_allocation(context)
        if runtime.runtime_partition_id != scope.runtime_partition_id:
            raise HTTPException(403)
        return runtime

    @asynccontextmanager
    async def live(scope: DevelopmentPreviewScope):
        try:
            runtime = await asyncio.to_thread(current_runtime, scope)
        except (ControlPlaneResolutionError, RuntimeResolutionError):
            raise HTTPException(403) from None
        adapter = integration.runtime_store_adapter
        binding = adapter.bind(runtime) if adapter is not None else bind_runtime_context(runtime)
        with binding:
            access = await require_access_and_level(
                runtime.runtime_user_key,
                scope.session_id,
                LEVEL_OWNER,
                official.permission_store,
                official.conversation_store,
            )
            conversation = access.conversation or await asyncio.to_thread(
                official.conversation_store.get_conversation, scope.session_id
            )
            if conversation is None:
                raise HTTPException(404)
            client = await _get_runner_client_for_resource_access(
                scope.session_id, conversation=conversation
            )
            if client is None:
                raise HTTPException(503)
            yield client

    # Enabling the feature requires its migrated table and the real restricted app login.
    with sessions.app() as db:
        db.execute(sa.text("SELECT id FROM saas_development_preview_grants WHERE false"))
    broker = DevelopmentPreviewBroker(
        grants=grants,
        root_domain=root,
        primary_origin=config.public_origin,
        release_incarnation=config.release_incarnation,
        principal=integration.auth_provider.get_principal,
        live=live,
    )
    app.state.development_preview_broker = broker
    app.add_middleware(DevelopmentPreviewHostMiddleware, broker=broker)
