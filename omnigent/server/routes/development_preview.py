"""Owner-authorized service discovery for an existing interactive session."""

from __future__ import annotations

import asyncio
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request

from omnigent.server.auth import LEVEL_OWNER, AuthProvider
from omnigent.server.routes._auth_helpers import require_access_and_level, require_user
from omnigent.server.routes._sessions.helpers import _get_runner_client_for_resource_access
from omnigent.stores import ConversationStore
from omnigent.stores.permission_store import PermissionStore


def register_development_preview_routes(
    router: APIRouter,
    *,
    conversation_store: ConversationStore,
    auth_provider: AuthProvider | None,
    permission_store: PermissionStore | None,
) -> None:
    async def owned(request: Request, session_id: str):
        user = require_user(request, auth_provider)
        access = await require_access_and_level(
            user, session_id, LEVEL_OWNER, permission_store, conversation_store
        )
        conversation = access.conversation or await asyncio.to_thread(
            conversation_store.get_conversation, session_id
        )
        if conversation is None:
            raise HTTPException(404)
        return conversation

    async def source(request: Request, session_id: str):
        conversation = await owned(request, session_id)
        client = await _get_runner_client_for_resource_access(
            session_id, conversation=conversation
        )
        if client is None:
            raise HTTPException(503, detail={"code": "preview_runner_unavailable"})
        response = await client.get(
            f"/v1/sessions/{quote(session_id, safe='')}/resources/development-preview",
            timeout=10,
        )
        if response.status_code != 200:
            raise HTTPException(503, detail={"code": "preview_discovery_unavailable"})
        return response.json()

    @router.get("/sessions/{session_id}/preview-services")
    async def services(request: Request, session_id: str):
        data = await source(request, session_id)
        data["preview_enabled"] = (
            getattr(request.app.state, "development_preview_broker", None) is not None
        )
        return data

    @router.post("/sessions/{session_id}/preview-services/{endpoint_id}/open")
    async def open_service(request: Request, session_id: str, endpoint_id: str):
        data = await source(request, session_id)
        endpoint = next((item for item in data["services"] if item["id"] == endpoint_id), None)
        if endpoint is None or endpoint["status"] != "ready":
            raise HTTPException(409, detail={"code": "preview_service_not_ready"})
        broker = getattr(request.app.state, "development_preview_broker", None)
        if broker is None:
            raise HTTPException(503, detail={"code": "preview_gateway_unavailable"})
        return await broker.open(request, session_id, endpoint_id)

    @router.delete("/sessions/{session_id}/development-previews/{preview_id}")
    async def stop_service(request: Request, session_id: str, preview_id: str):
        await owned(request, session_id)
        broker = getattr(request.app.state, "development_preview_broker", None)
        if broker is None:
            raise HTTPException(503, detail={"code": "preview_gateway_unavailable"})
        await broker.stop(request, session_id, preview_id)
        return {"status": "revoked"}
