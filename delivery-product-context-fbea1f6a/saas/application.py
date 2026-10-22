"""Downstream-only composition root for the official Omnigent FastAPI app."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, cast

from fastapi import FastAPI

import omnigent.server.app as official_app_module
from omnigent.server.app import create_app as create_official_app
from saas.control_plane.http_auth import SaasHttpIntegration


def _suppress_context_free_builtin_seed(app: FastAPI) -> None:
    """Skip the official single-workspace seed during one app's startup.

    The official lifespan resolves its seed helper at startup rather than at
    factory construction.  The downstream production process therefore wraps
    only the lifespan entry, restores the official helper before serving, and
    fails if another component changed that private compatibility point.
    """

    original_lifespan = app.router.lifespan_context
    expected_seed = official_app_module._ensure_default_agents

    def skip_seed(agent_store: Any, artifact_store: Any, agent_cache: Any) -> None:
        del agent_store, artifact_store, agent_cache

    @asynccontextmanager
    async def production_lifespan(app_instance: FastAPI):
        if official_app_module._ensure_default_agents is not expected_seed:
            raise RuntimeError("official built-in seed compatibility point drifted")
        official_app_module._ensure_default_agents = skip_seed
        try:
            async with original_lifespan(app_instance) as state:
                if official_app_module._ensure_default_agents is not skip_seed:
                    raise RuntimeError("official built-in seed compatibility point drifted")
                official_app_module._ensure_default_agents = expected_seed
                yield state
        finally:
            if official_app_module._ensure_default_agents is skip_seed:
                official_app_module._ensure_default_agents = expected_seed

    app.router.lifespan_context = cast(Any, production_lifespan)


def create_omnigent_saas_app(
    *,
    integration: SaasHttpIntegration,
    suppress_context_free_builtin_seed: bool = False,
    **official_app_dependencies: Any,
) -> FastAPI:
    """Build the official app with SaaS authentication and routes injected.

    The official runtime remains unaware of :mod:`saas`.  This composition
    root consumes only the two supported upstream extension seams:
    ``auth_provider`` and ``extra_routers``.  Middleware is installed after
    the official factory returns, before the application can start serving.

    Callers may supply additional official routers through
    ``extra_routers``.  Supplying a second auth provider is rejected because
    two independent identity authorities would make route behavior depend on
    which provider captured a request.
    """

    supplied_auth = official_app_dependencies.pop("auth_provider", None)
    if supplied_auth is not None and supplied_auth is not integration.auth_provider:
        raise ValueError("SaaS mode cannot combine independent auth providers")

    extra_routers = list(official_app_dependencies.pop("extra_routers", ()) or ())
    reserved_prefixes = {
        prefix.rstrip("/") for _router, prefix, _tags in integration.extra_routers
    }
    conflicting = {
        prefix.rstrip("/")
        for _router, prefix, _tags in extra_routers
        if prefix.rstrip("/") in reserved_prefixes
    }
    if conflicting:
        joined = ", ".join(sorted(conflicting))
        raise ValueError(f"router prefixes are reserved by the SaaS integration: {joined}")
    extra_routers.extend(integration.extra_routers)

    app = create_official_app(
        auth_provider=integration.auth_provider,
        extra_routers=extra_routers,
        **official_app_dependencies,
    )
    if suppress_context_free_builtin_seed:
        _suppress_context_free_builtin_seed(app)
    integration.install_middleware(app)
    app.state.saas_http_integration = integration
    return app
