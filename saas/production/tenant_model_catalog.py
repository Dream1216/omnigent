"""Read-only customer catalog mounted in the existing SaaS runtime router."""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import current_runtime_context
from saas.control_plane.http_auth import SaasAuthProvider, _require_principal
from saas.control_plane.tenant_model_catalog import TenantModelCatalog, TenantModelPageError
from saas.production.model_run_inference import require_current_customer_pricing


class ModelSelectionTarget(BaseModel):
    """A target hint, not customer-supplied tenant scope or execution authority."""

    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    harness: str = Field(min_length=1, max_length=128)
    host_type: Literal["external", "managed"]
    host_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    sandbox_provider: Literal["kubernetes", "agent_sandbox"] | None = None

    @model_validator(mode="after")
    def unambiguous_target(self):
        if self.host_type == "external":
            if self.host_id is None or self.sandbox_provider is not None:
                raise ValueError("external target required")
        elif self.host_id is not None or self.sandbox_provider is None:
            raise ValueError("sandbox target required")
        return self


class ModelCatalogPage(BaseModel):
    limit: int = Field(default=25, ge=1, le=100)
    cursor: UUID | None = None


def create_tenant_model_catalog_router(
    *,
    auth_provider: SaasAuthProvider,
    catalog: TenantModelCatalog,
    billing_sessions: sessionmaker[Session] | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.get("/managed-model-catalog")
    async def managed_model_catalog(request: Request, response: Response):
        principal = _require_principal(auth_provider, request)
        if principal.runtime_context is None:
            raise HTTPException(status_code=403, detail={"code": "runtime_context_required"})
        runtime = current_runtime_context()
        if runtime != principal.runtime_context:
            raise HTTPException(status_code=400, detail={"code": "model_catalog_request_invalid"})
        target = None
        try:
            if len(request.query_params.multi_items()) != len(request.query_params):
                raise ValueError("duplicate catalog parameters")
            params = dict(request.query_params)
            page = ModelCatalogPage.model_validate(
                {key: params.pop(key) for key in ("limit", "cursor") if key in params}
            )
            if params:
                target = ModelSelectionTarget.model_validate(params)
        except (ValidationError, ValueError):
            raise HTTPException(
                status_code=400, detail={"code": "model_catalog_request_invalid"}
            ) from None
        try:
            result = await asyncio.to_thread(
                catalog.page, runtime, limit=page.limit, cursor=page.cursor
            )
            models = list(result.items)
            runtime_enabled = False
            store = getattr(request.app.state, "production_interactive_conversation_store", None)
            if target is not None and store is not None:
                models, runtime_enabled = await store.preview_model_selection(
                    request,
                    models,
                    target,
                    check_pricing=partial(require_current_customer_pricing, billing_sessions)
                    if billing_sessions is not None
                    else None,
                )
        except TenantModelPageError:
            raise HTTPException(
                status_code=400, detail={"code": "model_catalog_request_invalid"}
            ) from None
        except Exception:  # noqa: BLE001 - no database/configuration details in a customer error.
            raise HTTPException(
                status_code=503, detail={"code": "managed_model_catalog_unavailable"}
            ) from None
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "models": models,
            "runtime_enabled": runtime_enabled,
            "next_cursor": result.next_cursor,
        }

    return router
