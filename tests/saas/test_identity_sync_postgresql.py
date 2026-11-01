from __future__ import annotations

import queue
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.orm import sessionmaker

from saas.control_plane import GlobalUser, IdentityManagementService
from saas.control_plane import federated_sessions as federated
from saas.control_plane import identity_sync as sync_module
from saas.control_plane.db_models import IdentityConnection
from saas.control_plane.identity import VerifiedIdentityAssertion
from saas.control_plane.identity_events import IdentitySyncError
from saas.control_plane.identity_inbox import IdentitySyncPolicy
from saas.control_plane.identity_sync import IdentityStateSyncService
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService
from tests.saas.test_casdoor_migration import _config
from tests.saas.test_identity_sync import ISSUER, SUBJECT, Provider, Source


@pytest.fixture
def postgres_sync(isolated_postgres_url):
    admin = sa.create_engine(isolated_postgres_url)
    login = "identity_sync_" + uuid4().hex
    password = secrets.token_hex(32)
    worker = None
    try:
        with admin.begin() as connection:
            command.upgrade(_config(connection), "head")
            connection.exec_driver_sql(
                (
                    Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
                ).read_text()
            )
            connection.exec_driver_sql(
                f'CREATE ROLE "{login}" LOGIN INHERIT NOSUPERUSER NOBYPASSRLS '
                f"PASSWORD '{password}'"
            )
            connection.exec_driver_sql(f'GRANT saas_authenticator TO "{login}"')
            database = connection.dialect.identifier_preparer.quote(
                connection.scalar(sa.text("SELECT current_database()"))
            )
            connection.exec_driver_sql(f'GRANT CONNECT ON DATABASE {database} TO "{login}"')
        worker = sa.create_engine(admin.url.set(username=login, password=password), pool_size=6)
        with worker.connect() as connection:
            row = connection.execute(
                sa.text(
                    "SELECT current_user,session_user,rolsuper,rolbypassrls FROM pg_roles "
                    "WHERE rolname=current_user"
                )
            ).one()
            assert row == (login, login, False, False)
            assert not connection.scalar(
                sa.text("SELECT has_table_privilege(current_user,'saas_tenants','INSERT')")
            )
        sessions = sessionmaker(worker, expire_on_commit=False)
        user_id = IdentityManagementService(sessions).provision_identity(
            VerifiedIdentityAssertion("casdoor", ISSUER, SUBJECT, "owner@example.test", True)
        )
        with sessions() as db:
            connection_id = db.scalar(sa.select(IdentityConnection.id))
        provider = Provider()
        service = IdentityStateSyncService(
            sessions,
            provider=provider,
            policy=IdentitySyncPolicy(issuer=ISSUER, organization="customers"),
        )
        yield (
            admin,
            Source(
                sessions,
                service,
                provider,
                user_id,
                connection_id,
                MembershipLifecycleService(sessions),
            ),
        )
    finally:
        if worker is not None:
            worker.dispose()
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP OWNED BY "{login}"')
            connection.exec_driver_sql(f'DROP ROLE IF EXISTS "{login}"')
        admin.dispose()


def _wait_for_database_lock(engine, pid):
    deadline = time.monotonic() + 10
    with engine.connect() as connection:
        while time.monotonic() < deadline:
            wait = connection.scalar(
                sa.text("SELECT wait_event_type FROM pg_stat_activity WHERE pid=:pid"),
                {"pid": pid},
            )
            if wait == "Lock":
                return
            connection.commit()
            time.sleep(0.02)
    pytest.fail("worker was not observed waiting on a PostgreSQL lock")


def test_independent_login_replicas_claim_once_and_expired_worker_cannot_commit(postgres_sync):
    _engine, source = postgres_sync
    now = datetime.now(timezone.utc)
    barrier = threading.Barrier(3)

    def claim(_):
        barrier.wait(timeout=10)
        return source.service.claim_due(now=now)

    with ThreadPoolExecutor(3) as pool:
        claims = [item for item in pool.map(claim, range(3)) if item is not None]
    assert len(claims) == 1
    later = now + source.service.policy.provider_lease
    successor = source.service.claim_due(now=later)
    assert successor is not None and successor.token != claims[0].token
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.apply(claims[0], source.provider.state, now=later)
    assert source.service.process(successor, now=later)


@pytest.mark.parametrize("first", ["sync", "login"])
@pytest.mark.parametrize("change", ["password", "disable"])
def test_state_apply_and_login_callback_serialize_without_leaving_valid_old_session(
    postgres_sync, monkeypatch, first, change
):
    engine, source = postgres_sync
    now = datetime.now(timezone.utc)
    source.sync(at=now)
    source.provider.state = replace(
        source.provider.state,
        **({"password_revision_sha256": "b" * 64} if change == "password" else {"disabled": True}),
    )
    claim = source.service.claim(source.connection_id, force=True, now=now)
    assert claim is not None
    original = federated._lock_fences
    locked, release = threading.Event(), threading.Event()
    waiting_pids = queue.Queue()

    @sa.event.listens_for(source.sessions, "after_begin")
    def backend_pid(_session, _transaction, connection):
        if threading.current_thread().name.startswith("sync-second"):
            waiting_pids.put(connection.scalar(sa.text("SELECT pg_backend_pid()")))

    def pause_first(db, **kwargs):
        fences = original(db, **kwargs)
        if threading.current_thread().name.startswith("sync-first"):
            locked.set()
            assert release.wait(15), "release gate timed out"
        return fences

    monkeypatch.setattr(federated, "_lock_fences", pause_first)
    monkeypatch.setattr(sync_module, "_lock_fences", pause_first)

    def apply():
        return source.service.process(claim, now=now)

    def login():
        return source.session(at=now, issued_at=now - timedelta(seconds=1))

    with (
        ThreadPoolExecutor(1, thread_name_prefix="sync-first") as a_pool,
        ThreadPoolExecutor(1, thread_name_prefix="sync-second") as b_pool,
    ):
        a = a_pool.submit(apply if first == "sync" else login)
        try:
            assert locked.wait(10)
            b = b_pool.submit(login if first == "sync" else apply)
            _wait_for_database_lock(engine, waiting_pids.get(timeout=10))
            release.set()
            if first == "sync":
                assert a.result(timeout=10).security_version == 2
                with pytest.raises(LifecycleError):
                    b.result(timeout=10)
            else:
                session = a.result(timeout=10)
                result = b.result(timeout=10)
                assert result.security_version == 2 and result.revoked_session_count == 1
                with pytest.raises(LifecycleError):
                    source.lifecycle.validate_auth_session(session.token, now=now)
        finally:
            release.set()


def test_lease_time_is_rechecked_after_waiting_for_account_lock(postgres_sync, monkeypatch):
    engine, source = postgres_sync
    now = datetime.now(timezone.utc)
    claim = source.service.claim_due(now=now)
    assert claim is not None
    waiting_pids = queue.Queue()

    @sa.event.listens_for(source.sessions, "after_begin")
    def backend_pid(_session, _transaction, connection):
        if threading.current_thread().name.startswith("expired-sync"):
            waiting_pids.put(connection.scalar(sa.text("SELECT pg_backend_pid()")))

    with ThreadPoolExecutor(1, thread_name_prefix="expired-sync") as pool:
        with engine.begin() as connection:
            connection.execute(
                sa.select(GlobalUser.id).where(GlobalUser.id == source.user_id).with_for_update()
            )
            pending = pool.submit(source.service.apply, claim, source.provider.state)
            _wait_for_database_lock(engine, waiting_pids.get(timeout=10))
            monkeypatch.setattr(sync_module, "_utc", lambda value=None: claim.lease_expires_at)
        with pytest.raises(IdentitySyncError, match="claim_stale"):
            pending.result(timeout=10)


def test_network_read_does_not_hold_account_lock_and_changed_account_rejects_result(postgres_sync):
    engine, source = postgres_sync
    now = datetime.now(timezone.utc)
    old = source.session(at=now)

    def mutate_during_read():
        with ThreadPoolExecutor(1) as pool:

            def change():
                with engine.begin() as connection:
                    connection.exec_driver_sql("SET LOCAL lock_timeout='2s'")
                    connection.execute(
                        sa.update(GlobalUser)
                        .where(GlobalUser.id == source.user_id)
                        .values(security_version=GlobalUser.security_version + 1)
                    )

            pool.submit(change).result(timeout=5)

    source.provider.before_read = mutate_during_read
    claim = source.service.claim_due(now=now)
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.process(claim, now=now)
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token, now=now)
