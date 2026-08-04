"""Downstream-only composition root for the official Omnigent FastAPI app."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from omnigent.server.app import create_app as create_official_app
from saas.control_plane.http_auth import SaasHttpIntegration


def create_omnigent_saas_app(
    *,
    integration: SaasHttpIntegration,
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
    if any(prefix.rstrip("/") == "/saas" for _router, prefix, _tags in extra_routers):
        raise ValueError("the /saas router prefix is reserved by the SaaS integration")
    extra_routers.append(integration.extra_router)

    app = create_official_app(
        auth_provider=integration.auth_provider,
        extra_routers=extra_routers,
        **official_app_dependencies,
    )
    integration.install_middleware(app)
    app.state.saas_http_integration = integration
    return app
