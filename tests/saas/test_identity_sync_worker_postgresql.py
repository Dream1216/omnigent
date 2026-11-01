from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from saas.control_plane.identity_sync_worker import IdentitySyncWorker
from tests.saas.test_identity_sync_postgresql import postgres_sync as postgres_sync
from tests.saas.test_identity_sync_worker import wait_until


def test_independent_authenticator_workers_reconcile_and_measure_lag_without_manual_ticks(
    postgres_sync,
):
    _admin, source = postgres_sync
    source.service.policy = replace(source.service.policy, reconcile_interval=timedelta(seconds=1))
    old = source.session(at=datetime.now(timezone.utc))
    worker = IdentitySyncWorker(source.service, concurrency=3)
    try:
        worker.start()
        wait_until(lambda: worker.snapshot()["unchecked_connections"] == 0)
        assert source.lifecycle.validate_auth_session(old.token)
        source.provider.state = replace(source.provider.state, disabled=True)

        def revoked():
            from saas.control_plane.lifecycle import LifecycleError

            try:
                source.lifecycle.validate_auth_session(old.token)
            except LifecycleError:
                return True
            return False

        wait_until(revoked)
        data = worker.snapshot()
        assert worker.healthy() and data["connections"] == 1 and data["unchecked_connections"] == 0
        assert data["reconciled_total"] >= 2 and data["reconcile_age_seconds"] < 5
    finally:
        worker.stop()
