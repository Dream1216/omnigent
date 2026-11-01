"""Private durable ingress and periodic worker, independent of product runtime health."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from saas.control_plane.identity_events_http import create_identity_event_router
from saas.control_plane.identity_inbox import IdentitySyncPolicy
from saas.control_plane.identity_private_channel import PrivateIdentityKeys
from saas.control_plane.identity_sync import IdentityStateSyncService
from saas.control_plane.identity_sync_worker import IdentitySyncWorker
from saas.production.credential_worker_config import (
    CredentialWorkerSessions,
    create_credential_worker_sessions,
)
from saas.production.identity_process_config import IdentityWorkerConfig
from saas.production.identity_read_client import IdentityReadClient
from saas.production.server import verify_installed_build_lineage


def create_identity_sync_app(worker: IdentitySyncWorker, *, keys: PrivateIdentityKeys) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app):
        worker.start()
        try:
            yield
        finally:
            await run_in_threadpool(worker.stop)

    app = FastAPI(lifespan=lifespan, openapi_url=None, docs_url=None, redoc_url=None)
    app.include_router(create_identity_event_router(worker.service.inbox, keys=keys))

    @app.get("/healthz")
    async def health():
        status = 200 if worker.healthy() else 503
        return JSONResponse(
            {"status": "ok" if status == 200 else "unavailable"},
            status_code=status,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/readyz")
    async def ready():
        # Provider failure does not prevent committing incoming notifications.
        try:
            await run_in_threadpool(worker.snapshot)
            return await health()
        except Exception:  # noqa: BLE001 - keep DB details out of private probes.
            return JSONResponse({"status": "unavailable"}, status_code=503)

    @app.get("/metrics")
    async def metrics():
        try:
            data = await run_in_threadpool(worker.snapshot)
        except Exception:  # noqa: BLE001 - metrics never serialize SQL or user values.
            return Response(
                "identity_sync_metrics_unavailable 1\n", status_code=503, media_type="text/plain"
            )
        body = "".join(
            f"omnigent_identity_sync_{key} {value}\n" for key, value in sorted(data.items())
        )
        return Response(
            body, media_type="text/plain; version=0.0.4", headers={"Cache-Control": "no-store"}
        )

    return app


def build_identity_sync_server(
    config: IdentityWorkerConfig,
) -> tuple[FastAPI, CredentialWorkerSessions]:
    verify_installed_build_lineage(config.release)
    sessions = create_credential_worker_sessions(config.release)
    try:
        service = IdentityStateSyncService(
            sessions.authenticator,
            provider=IdentityReadClient(config.reader),
            policy=IdentitySyncPolicy(
                issuer=config.release.identity.issuer,
                organization=config.release.identity.organization,
                reconcile_interval=timedelta(seconds=config.reconcile_seconds),
            ),
        )
        worker = IdentitySyncWorker(
            service, concurrency=config.concurrency, poll_seconds=config.poll_seconds
        )
        worker.snapshot()
        return create_identity_sync_app(worker, keys=config.webhook_keys), sessions
    except Exception:
        sessions.close()
        raise
