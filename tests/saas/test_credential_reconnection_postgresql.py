from __future__ import annotations

import base64
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
import sqlalchemy as sa

from saas.control_plane import GlobalUser
from saas.control_plane.credential_migration import CredentialMigrationError
from saas.control_plane.credential_reconnection import RECONNECTION_SIGNATURE_DOMAIN
from saas.control_plane.credential_recovery import recovery_grant_payload
from saas.control_plane.db_models import ControlPlaneOutboxEvent, IdentityConnection
from tests.saas.test_credential_fences_postgresql import postgres_source as postgres_source
from tests.saas.test_credential_fences_postgresql import wait_for_lock
from tests.saas.test_credential_migration import NOW
from tests.saas.test_credential_reconnection import recovered, sign


def test_two_verified_return_workers_commit_one_reconnection(postgres_source):
    _engine, source, invoke, _prefix = postgres_source
    service, provider, key, request = recovered(source)
    token = sign(key, request)
    barrier = threading.Barrier(2)
    provider.hook = lambda: barrier.wait(timeout=10)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                invoke, "reconnect", lambda: service.reconnect(signed_grant=token, now=NOW)
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=15) for future in futures]
    assert results == [UUID(request["connection_id"])] * 2
    with source.sessions() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.event_type
                    == "identity.credential_migration.reconnected",
                )
            )
            == 1
        )
        assert (
            db.get(GlobalUser, source.user_id).security_version
            == request["expected_security_version"] + 1
        )


def test_return_grant_expiring_while_waiting_for_lock_cannot_reactivate(postgres_source):
    engine, source, invoke, prefix = postgres_source
    service, provider, key, request = recovered(source)
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=2)
    document = {
        **request,
        "schema_version": 1,
        "grant_id": str(UUID(int=500)),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
    }
    payload = recovery_grant_payload(document)
    parts = [
        base64.urlsafe_b64encode(value).decode().rstrip("=")
        for value in (
            payload,
            key.sign(RECONNECTION_SIGNATURE_DOMAIN + payload),
        )
    ]
    token = ".".join(["v1", "offline-return", *parts])
    reached, release = threading.Event(), threading.Event()

    def pause():
        reached.set()
        assert release.wait(10)

    provider.hook = pause
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(invoke, "return", lambda: service.reconnect(signed_grant=token))
        try:
            assert reached.wait(10)
            with engine.begin() as held:
                held.execute(
                    sa.text("SELECT id FROM saas_global_users WHERE id=:id FOR UPDATE"),
                    {"id": source.user_id},
                )
                release.set()
                wait_for_lock(engine, prefix + "-return")
                time.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + 0.1)
        finally:
            release.set()
        with pytest.raises(CredentialMigrationError, match="grant_invalid"):
            future.result(timeout=10)
    with source.sessions() as db:
        assert db.get(IdentityConnection, UUID(request["connection_id"])).status == "revoked"
        assert (
            db.get(GlobalUser, source.user_id).security_version
            == request["expected_security_version"]
        )
