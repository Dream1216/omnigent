from __future__ import annotations

import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.identity_event_models import IdentityEventInboxRecord
from saas.control_plane.identity_replay import IdentityReplayError
from tests.saas.test_identity_replay import reviewed, sign
from tests.saas.test_identity_sync_postgresql import _wait_for_database_lock
from tests.saas.test_identity_sync_postgresql import postgres_sync as postgres_sync


def test_parallel_approved_replays_use_one_atomic_audit_and_one_attempt_budget_reset(
    postgres_sync,
):
    _admin, source = postgres_sync
    now = datetime.now(timezone.utc)
    service, key, document, inbox_id = reviewed(source, at=now)
    token = sign(key, document)
    barrier = threading.Barrier(2)

    def replay():
        barrier.wait(timeout=10)
        return service.replay(token)

    with ThreadPoolExecutor(2) as pool:
        first, second = [
            future.result(timeout=15) for future in (pool.submit(replay), pool.submit(replay))
        ]
    assert first["audit_id"] == second["audit_id"]
    assert sorted([first["duplicate"], second["duplicate"]]) == [False, True]
    with source.sessions() as db:
        record = db.get(IdentityEventInboxRecord, inbox_id)
        assert record.status == "pending" and record.attempt_count == 0
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.event_type == "identity.notification.replayed",
                )
            )
            == 1
        )
        assert not db.scalar(
            sa.text("SELECT has_table_privilege(current_user,'saas_tenants','INSERT')")
        )


def test_approval_expiring_during_observed_account_lock_wait_cannot_replay(postgres_sync):
    admin, source = postgres_sync
    now = datetime.now(timezone.utc)
    service, key, document, inbox_id = reviewed(source, at=now)
    document["expires_at"] = (now + timedelta(seconds=3)).isoformat()
    token = sign(key, document)
    pids = queue.Queue()

    def backend_pid(_session, _transaction, connection):
        if threading.current_thread().name.startswith("replay-expiry"):
            pids.put(connection.scalar(sa.text("SELECT pg_backend_pid()")))

    sa.event.listen(source.sessions, "after_begin", backend_pid)
    try:
        with admin.connect() as holder:
            transaction = holder.begin()
            holder.execute(
                sa.select(IdentityEventInboxRecord.id)
                .where(
                    IdentityEventInboxRecord.id == inbox_id,
                )
                .with_for_update()
            ).one()
            with ThreadPoolExecutor(1, thread_name_prefix="replay-expiry") as pool:
                future = pool.submit(service.replay, token)
                _wait_for_database_lock(admin, pids.get(timeout=10))
                while datetime.now(timezone.utc) <= now + timedelta(seconds=3.1):
                    time.sleep(0.02)
                transaction.commit()
                with pytest.raises(IdentityReplayError, match="grant_invalid"):
                    future.result(timeout=10)
    finally:
        sa.event.remove(source.sessions, "after_begin", backend_pid)
    with source.sessions() as db:
        assert db.get(IdentityEventInboxRecord, inbox_id).status == "dead"
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.event_type == "identity.notification.replayed",
                )
            )
            == 0
        )
