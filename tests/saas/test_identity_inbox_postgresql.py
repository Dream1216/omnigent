from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from sqlalchemy.orm import sessionmaker

from saas.control_plane.identity_inbox import IdentityEventInboxService, IdentitySyncPolicy
from tests.saas.test_casdoor_identity_events import NOW
from tests.saas.test_casdoor_migration import _config
from tests.saas.test_identity_inbox import event


def test_postgresql_concurrent_replicas_deduplicate_and_only_one_worker_claims(
    isolated_postgres_url,
):
    engine = sa.create_engine(isolated_postgres_url)
    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), "head")
            connection.exec_driver_sql(
                (
                    Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
                ).read_text()
            )
        sessions = sessionmaker(engine, expire_on_commit=False)

        @sa.event.listens_for(sessions, "after_begin")
        def role(_session, _transaction, connection):
            connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")

        service = IdentityEventInboxService(
            sessions,
            policy=IdentitySyncPolicy(
                issuer="https://auth.example.test",
                organization="customers",
            ),
        )
        barrier = threading.Barrier(3)

        def ingest(_):
            barrier.wait(timeout=10)
            return service.ingest(event(), now=NOW)

        with ThreadPoolExecutor(max_workers=3) as pool:
            receipts = list(pool.map(ingest, range(3)))
        assert len({receipt.id for receipt in receipts}) == 1
        assert sum(receipt.duplicate for receipt in receipts) == 2
        barrier = threading.Barrier(3)

        def claim(_):
            barrier.wait(timeout=10)
            return service.claim_next(now=NOW)

        with ThreadPoolExecutor(max_workers=3) as pool:
            claims = [item for item in pool.map(claim, range(3)) if item is not None]
        assert len(claims) == 1
        later = NOW + service.policy.event_lease + timedelta(seconds=1)
        successor = service.claim_next(now=later)
        assert successor is not None and successor.token != claims[0].token
        assert service.finish(successor, processed_connections=1, now=later).status == "completed"
        assert service.claim_next(now=later) is None
    finally:
        engine.dispose()
