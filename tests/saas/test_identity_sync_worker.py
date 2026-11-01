from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from saas.control_plane import GlobalUser, IdentityManagementService, SaasBase
from saas.control_plane.db_models import IdentityConnection, PasswordCredential, TenantMembership
from saas.control_plane.federated_sessions import ExternalSessionIdentity
from saas.control_plane.identity import VerifiedIdentityAssertion
from saas.control_plane.identity_event_models import IdentityProviderStateRecord
from saas.control_plane.identity_events import IdentityNotification, IdentitySyncError
from saas.control_plane.identity_events_http import IdentityEventIngressKeys
from saas.control_plane.identity_inbox import IdentitySyncPolicy
from saas.control_plane.identity_sync import IdentityStateSyncService
from saas.control_plane.identity_sync_worker import IdentitySyncWorker
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService
from saas.production.identity_sync_server import create_identity_sync_app
from tests.saas.test_casdoor_identity_events import notification
from tests.saas.test_identity_sync import ISSUER, SUBJECT, Provider


def wait_until(check):
    deadline = time.monotonic() + 10
    while not check():
        assert time.monotonic() < deadline, (
            "identity worker did not converge within the test deadline"
        )
        time.sleep(0.025)


@pytest.fixture
def source(tmp_path):
    engine = sa.create_engine(
        "sqlite:///" + str(tmp_path / "worker.db"), connect_args={"check_same_thread": False}
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    user = IdentityManagementService(sessions).provision_identity(
        VerifiedIdentityAssertion("casdoor", ISSUER, SUBJECT, "owner@example.test", True)
    )
    provider = Provider()
    service = IdentityStateSyncService(
        sessions,
        provider=provider,
        policy=IdentitySyncPolicy(
            issuer=ISSUER,
            organization="customers",
            reconcile_interval=timedelta(seconds=1),
            max_attempts=2,
        ),
    )
    worker = IdentitySyncWorker(service, concurrency=1)
    lifecycle = MembershipLifecycleService(sessions)
    now = datetime.now(timezone.utc)
    issued = lifecycle.issue_auth_session(
        user_id=user,
        authn_method="oidc:casdoor",
        now=now,
        expires_at=now + timedelta(hours=1),
        external_identity=ExternalSessionIdentity("casdoor", ISSUER, SUBJECT, now),
    )
    try:
        yield worker, provider, sessions, user, lifecycle, issued
    finally:
        worker.stop()
        engine.dispose()


def test_background_reconciliation_revokes_missed_disable_without_manual_ticks(source):
    worker, provider, sessions, user, lifecycle, issued = source
    worker.start()
    wait_until(lambda: worker.snapshot()["unchecked_connections"] == 0)
    assert lifecycle.validate_auth_session(issued.token)
    provider.state = replace(provider.state, disabled=True)

    def revoked():
        try:
            lifecycle.validate_auth_session(issued.token)
        except LifecycleError:
            return True
        return False

    wait_until(revoked)
    assert worker.healthy() and worker.snapshot()["reconciled_total"] >= 2
    with sessions() as db:
        assert db.get(GlobalUser, user).credential_owner == "casdoor"
        assert db.get(GlobalUser, user).status == "active"
        assert db.scalar(sa.select(sa.func.count()).select_from(PasswordCredential)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(TenantMembership)) == 0


def test_provider_outage_keeps_private_ingress_ready_persists_events_and_preserves_sessions(
    source,
):
    worker, provider, _sessions, _user, lifecycle, issued = source
    leaked = "lowercaseprivatesecretfromprovider"
    provider.error = IdentitySyncError(leaked, retryable=True)
    app = create_identity_sync_app(worker, keys=IdentityEventIngressKeys({"current": "w" * 40}))
    with TestClient(app, base_url="https://private.example.test") as api:
        wait_until(lambda: worker.snapshot()["failures_total"] > 0)
        response = api.post(
            "/saas/identity-events/casdoor",
            content=notification(),
            headers={
                "Content-Type": "application/json",
                "X-Omnigent-Identity-Event-Key-Id": "current",
                "X-Omnigent-Identity-Event-Secret": "w" * 40,
            },
        )
        assert response.status_code == 200 and response.json()["receipt_id"]
        assert api.get("/readyz").status_code == 200
        metrics = api.get("/metrics")
        assert metrics.status_code == 200
        assert all(
            term not in metrics.text
            for term in (leaked, SUBJECT, "owner@example.test", "w" * 40, "postgresql")
        )
        assert lifecycle.validate_auth_session(issued.token)
        with _sessions() as db:
            state = db.scalar(sa.select(IdentityProviderStateRecord))
            assert state.last_error_code == "identity_sync_failed"
        provider.error = None
        provider.state = replace(provider.state, disabled=True)

        def revoked():
            try:
                lifecycle.validate_auth_session(issued.token)
            except LifecycleError:
                return True
            return False

        wait_until(revoked)
        wait_until(lambda: worker.snapshot()["event_backlog"] == 0)
    assert not worker.healthy()


def test_unknown_mapping_reaches_dead_letter_without_mutating_unrelated_identity(source):
    worker, _provider, _sessions, _user, lifecycle, issued = source
    now = datetime.now(timezone.utc)
    worker.service.inbox.ingest(
        IdentityNotification(
            "unmapped-event",
            "delete-user",
            "customers",
            "unmapped-subject",
            "unknown-user",
            now,
            True,
        )
    )
    worker.start()
    wait_until(lambda: worker.snapshot()["dead_events_total"] == 1)
    stats = worker.snapshot()
    assert stats["event_backlog"] == 0 and stats["event_age_seconds"] == 0
    assert lifecycle.validate_auth_session(issued.token)


def test_snapshot_tracks_initial_age_and_excludes_product_inactive_or_locally_revoked_identities(
    source,
):
    worker, _provider, sessions, user, _lifecycle, _issued = source
    past = datetime.now(timezone.utc) - timedelta(seconds=301)
    with sessions.begin() as db:
        db.execute(sa.update(IdentityConnection).values(created_at=past))
    initial = worker.snapshot()
    assert initial["unchecked_connections"] == 1 and initial["reconcile_age_seconds"] >= 300
    with sessions.begin() as db:
        db.get(GlobalUser, user).status = "suspended"
    assert worker.snapshot()["connections"] == 0
    worker.start()
    time.sleep(0.1)
    assert worker.snapshot()["reconciled_total"] == 0


def test_metrics_failure_does_not_expose_database_details_or_authenticate_webhook(
    source, monkeypatch
):
    worker, _provider, _sessions, _user, _lifecycle, _issued = source
    app = create_identity_sync_app(worker, keys=IdentityEventIngressKeys({"current": "w" * 40}))
    with TestClient(app, base_url="https://private.example.test") as api:

        def failed():
            raise RuntimeError("database credential must never leave metrics")

        monkeypatch.setattr(worker, "snapshot", failed)
        assert api.get("/readyz").status_code == 503
        response = api.get("/metrics")
        assert response.status_code == 503 and "credential" not in response.text
        assert (
            api.post("/saas/identity-events/casdoor", json=json.loads(notification())).status_code
            == 401
        )


def test_worker_has_one_start_stop_lifecycle_and_bounded_capacity(source):
    worker, _provider, _sessions, _user, _lifecycle, _issued = source
    for value in (0, 17, True):
        with pytest.raises(ValueError):
            IdentitySyncWorker(worker.service, concurrency=value)
    worker.start()
    with pytest.raises(RuntimeError):
        worker.start()
    worker.stop()
    with pytest.raises(RuntimeError):
        worker.start()
    assert not worker.healthy()
