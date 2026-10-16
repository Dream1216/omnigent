"""Read-only customer catalog mounted in the existing SaaS runtime router."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request, Response

from saas.compatibility import current_runtime_context
from saas.control_plane.http_auth import SaasAuthProvider, _require_principal
from saas.control_plane.tenant_model_catalog import TenantModelCatalog


def create_tenant_model_catalog_router(
    *, auth_provider: SaasAuthProvider, catalog: TenantModelCatalog
) -> APIRouter:
    router = APIRouter()

    @router.get("/managed-model-catalog")
    async def managed_model_catalog(request: Request, response: Response):
        principal = _require_principal(auth_provider, request)
        if principal.runtime_context is None:
            raise HTTPException(status_code=403, detail={"code": "runtime_context_required"})
        runtime = current_runtime_context()
        if runtime != principal.runtime_context or request.query_params:
            raise HTTPException(status_code=400, detail={"code": "model_catalog_request_invalid"})
        try:
            models = await asyncio.to_thread(catalog.list, runtime)
        except Exception:  # noqa: BLE001 - no database/configuration details in a customer error.
            raise HTTPException(
                status_code=503, detail={"code": "managed_model_catalog_unavailable"}
            ) from None
        response.headers["Cache-Control"] = "private, no-store"
        return {"models": models, "runtime_enabled": False}

    return router
