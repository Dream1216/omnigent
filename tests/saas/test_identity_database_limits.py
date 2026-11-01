from __future__ import annotations

import time
from dataclasses import replace

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError, TimeoutError

from saas.control_plane import GlobalUser
from saas.production.credential_worker_config import (
    CredentialWorkerDatabaseLimits,
    create_credential_worker_engine,
)
from tests.saas.test_identity_sync_postgresql import postgres_sync as postgres_sync


@pytest.mark.parametrize(
    "change",
    [
        {"pool_size": 0},
        {"pool_size": 9},
        {"pool_size": True},
        {"connect_timeout_seconds": 0},
        {"pool_timeout_seconds": 6},
        {"lock_timeout_ms": 0},
        {"lock_timeout_ms": 10000},
        {"statement_timeout_ms": 10001},
        {"idle_transaction_timeout_ms": 30000},
    ],
)
def test_identity_database_limits_cannot_disable_or_expand_operation_budgets(change):
    with pytest.raises(ValueError):
        replace(CredentialWorkerDatabaseLimits(), **change)


def test_real_authenticator_connections_have_bounded_locks_statements_pool_and_rollback(
    postgres_sync,
):
    admin, source = postgres_sync
    limits = CredentialWorkerDatabaseLimits(
        pool_size=1,
        pool_timeout_seconds=1,
        lock_timeout_ms=150,
        statement_timeout_ms=300,
        idle_transaction_timeout_ms=500,
    )
    bounded = create_credential_worker_engine(
        source.sessions.kw["bind"].url.render_as_string(hide_password=False), limits=limits
    )
    try:
        with bounded.connect() as connection:
            assert connection.scalar(sa.text("SHOW lock_timeout")) == "150ms"
            assert connection.scalar(sa.text("SHOW statement_timeout")) == "300ms"
            assert (
                connection.scalar(sa.text("SHOW idle_in_transaction_session_timeout")) == "500ms"
            )
            assert connection.scalar(sa.text("SELECT current_user=session_user"))
            connection.rollback()
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                with bounded.connect():
                    pass
            assert time.monotonic() - started < 3
        with admin.begin() as holder:
            holder.execute(
                sa.select(GlobalUser.id).where(GlobalUser.id == source.user_id).with_for_update()
            )
            with bounded.begin() as waiting:
                started = time.monotonic()
                with pytest.raises(DBAPIError) as failure:
                    waiting.execute(
                        sa.update(GlobalUser)
                        .where(GlobalUser.id == source.user_id)
                        .values(security_version=GlobalUser.security_version + 1)
                    )
                assert failure.value.orig.sqlstate == "55P03" and time.monotonic() - started < 2
                waiting.rollback()
        with bounded.begin() as waiting:
            with pytest.raises(DBAPIError) as failure:
                waiting.execute(sa.text("SELECT pg_sleep(1)"))
            assert failure.value.orig.sqlstate == "57014"
            waiting.rollback()
        with bounded.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(GlobalUser.security_version).where(GlobalUser.id == source.user_id)
                )
                == 1
            )
        with bounded.connect() as idle:
            idle.execute(sa.text("SELECT 1"))
            time.sleep(0.7)
            with pytest.raises(DBAPIError):
                idle.execute(sa.text("SELECT 1"))
            idle.rollback()
        with bounded.connect() as replacement:
            assert replacement.scalar(sa.text("SELECT 1")) == 1
    finally:
        bounded.dispose()
