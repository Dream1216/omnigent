from __future__ import annotations

import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.customer_auth_restore import (
    CustomerAuthRestoreError,
    CustomerAuthRestoreService,
    restore_review_sha256,
)
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    OidcSessionFence,
)
from saas.control_plane.lifecycle import LifecycleError
from tests.saas.test_customer_auth_restore import pending_oidc
from tests.saas.test_identity_sync_postgresql import _wait_for_database_lock
from tests.saas.test_identity_sync_postgresql import postgres_sync as postgres_sync


def test_restricted_login_can_atomically_invalidate_customer_restore_and_preserve_new_sessions(
    postgres_sync,
):
    _admin, source = postgres_sync
    now = datetime.now(timezone.utc)
    source.sync(at=now)
    old = source.session(at=now)
    pending_oidc(source)
    service = CustomerAuthRestoreService(source.sessions, product_revision="9" * 40)
    review = service.review(restore_id=uuid4(), backup_set_sha256="a" * 64)
    digest = restore_review_sha256(review)
    first = service.apply(review, expected_sha256=digest, review_reference="owned/RESTORE-123")
    assert (
        first["counts"]["users"] == 1
        and first["counts"]["sessions"] == 1
        and first["counts"]["oidc_transactions"] == 1
    )
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token)
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "casdoor"
        assert db.get(GlobalUser, source.user_id).security_version == 2
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(AuthSessionRecord)
                .where(AuthSessionRecord.revoked_at.is_(None))
            )
            == 0
        )
        assert db.scalar(
            sa.text(
                "select not rolsuper and not rolbypassrls from pg_roles where rolname=current_user"
            )
        )
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(OidcSessionFence)
                .where(OidcSessionFence.kind == "subject")
            )
            >= 1
        )
    fresh_at = datetime.now(timezone.utc) + timedelta(seconds=1)
    fresh = source.session(at=fresh_at, issued_at=fresh_at)
    assert service.apply(review, expected_sha256=digest, review_reference="owned/RESTORE-123")[
        "duplicate"
    ]
    assert source.lifecycle.validate_auth_session(fresh.token, now=fresh_at)


def test_review_expiry_during_observed_row_lock_wait_prevents_any_restore_mutation(
    postgres_sync,
):
    admin, source = postgres_sync
    now = datetime.now(timezone.utc)
    service = CustomerAuthRestoreService(source.sessions, product_revision="9" * 40)
    review = service.review(restore_id=uuid4(), backup_set_sha256="a" * 64)
    review["expires_at"] = (now + timedelta(seconds=3)).isoformat()
    digest = restore_review_sha256(review)
    pids = queue.Queue()

    def backend(_session, _transaction, connection):
        if threading.current_thread().name.startswith("restore-expiry"):
            pids.put(connection.scalar(sa.text("select pg_backend_pid()")))

    sa.event.listen(source.sessions, "after_begin", backend)
    try:
        with admin.connect() as holder:
            transaction = holder.begin()
            holder.execute(
                sa.select(GlobalUser.id).where(GlobalUser.id == source.user_id).with_for_update()
            ).one()
            with ThreadPoolExecutor(1, thread_name_prefix="restore-expiry") as pool:
                future = pool.submit(
                    service.apply,
                    review,
                    expected_sha256=digest,
                    review_reference="owned/RESTORE-123",
                )
                _wait_for_database_lock(admin, pids.get(timeout=10))
                while datetime.now(timezone.utc) <= now + timedelta(seconds=3.1):
                    time.sleep(0.02)
                transaction.commit()
                with pytest.raises(CustomerAuthRestoreError, match="review_invalid"):
                    future.result(timeout=10)
    finally:
        sa.event.remove(source.sessions, "after_begin", backend)
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).security_version == 1
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.event_type == "identity.customer_restore.invalidated"
                )
            )
            == 0
        )
