from __future__ import annotations

import queue
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import federated_sessions as federated
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    IdentityConflict,
    OidcSessionFence,
)
from saas.control_plane.federated_sessions import (
    ExternalSessionIdentity,
    FederatedSessionService,
    VerifiedLogoutEvent,
)
from saas.control_plane.identity import IdentityManagementService, VerifiedIdentityAssertion
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService


@pytest.fixture
def postgres_federation(
    isolated_postgres_url: str,
) -> Iterator[tuple[sa.Engine, sessionmaker[Session]]]:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url, pool_size=6)
    try:
        with engine.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
        sessions = sessionmaker(engine, expire_on_commit=False)

        @sa.event.listens_for(sessions, "after_begin")
        def authenticator(
            _session: Session, _transaction: object, connection: sa.Connection
        ) -> None:
            connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")

        yield engine, sessions
    finally:
        engine.dispose()


@pytest.mark.parametrize("first", ["logout", "login"])
@pytest.mark.parametrize("parent_bound", [False, True], ids=["unbound", "parent"])
def test_real_postgresql_login_logout_race_cannot_leave_a_live_old_identity_session(
    postgres_federation: tuple[sa.Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
    first: str,
    parent_bound: bool,
) -> None:
    engine, sessions = postgres_federation
    user = (
        IdentityManagementService(sessions)
        .resolve_verified_login(
            VerifiedIdentityAssertion(
                provider="casdoor",
                issuer="https://auth.example.test",
                subject="race-user",
                email="race@example.test",
                email_verified=True,
            )
        )
        .user_id
    )
    assert user is not None
    now = datetime.now(timezone.utc)
    identity = ExternalSessionIdentity(
        "casdoor", "https://auth.example.test", "race-user", now - timedelta(seconds=1)
    )
    event = VerifiedLogoutEvent("casdoor", identity.issuer, "race-event", now, "race-user", None)
    lifecycle = MembershipLifecycleService(sessions)
    parent = (
        lifecycle.issue_auth_session(
            user_id=user,
            authn_method="oidc:casdoor",
            expires_at=now + timedelta(hours=1),
            external_identity=identity,
        )
        if parent_bound
        else None
    )
    service = FederatedSessionService(sessions)
    locked, release = threading.Event(), threading.Event()
    original = federated._lock_fences
    waiting_pids: queue.Queue[int] = queue.Queue()

    @sa.event.listens_for(sessions, "after_begin")
    def backend_pid(_session: Session, _transaction: object, connection: sa.Connection) -> None:
        if threading.current_thread().name.startswith("federation-second"):
            waiting_pids.put(connection.scalar(sa.text("SELECT pg_backend_pid()")))

    def pause_first(db: Session, **kwargs):
        fences = original(db, **kwargs)
        is_logout = "event" in fences
        if is_logout == (first == "logout"):
            locked.set()
            assert release.wait(15), "release gate timed out"
        return fences

    monkeypatch.setattr(federated, "_lock_fences", pause_first)

    def login():
        return lifecycle.issue_auth_session(
            user_id=user,
            authn_method="oidc:casdoor",
            expires_at=now + timedelta(hours=1),
            external_identity=identity,
            required_parent_session_id=parent.session_id if parent else None,
        )

    def logout():
        return service.revoke(event, now=now)

    with (
        ThreadPoolExecutor(1, thread_name_prefix="federation-first") as first_pool,
        ThreadPoolExecutor(1, thread_name_prefix="federation-second") as second_pool,
    ):
        a = first_pool.submit(logout if first == "logout" else login)
        try:
            assert locked.wait(10), "first transaction never acquired its fence"
            b = second_pool.submit(login if first == "logout" else logout)
            pid = waiting_pids.get(timeout=10)
            deadline = time.monotonic() + 10
            with engine.connect() as connection:
                while time.monotonic() < deadline:
                    waiting = connection.scalar(
                        sa.text("SELECT wait_event_type FROM pg_stat_activity WHERE pid=:pid"),
                        {"pid": pid},
                    )
                    if waiting == "Lock":
                        break
                    connection.commit()
                    time.sleep(0.02)
                else:
                    pytest.fail("second transaction was not observed waiting on a PostgreSQL lock")
            release.set()
            if first == "logout":
                assert a.result(timeout=10) is False
                with pytest.raises(LifecycleError, match="identity session ended"):
                    b.result(timeout=10)
            else:
                issued = a.result(timeout=10)
                assert b.result(timeout=10) is False
                with pytest.raises(LifecycleError):
                    lifecycle.validate_auth_session(issued.token)
        finally:
            release.set()
    with sessions() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(AuthSessionRecord)
                .where(AuthSessionRecord.revoked_at.is_(None))
            )
            == 0
        )
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(OidcSessionFence)
                .where(OidcSessionFence.kind == "event")
            )
            == 1
        )


def test_real_postgresql_fence_authority_and_external_mapping_are_not_customer_controlled(
    postgres_federation: tuple[sa.Engine, sessionmaker[Session]],
) -> None:
    engine, sessions = postgres_federation
    with engine.begin() as connection:
        row = connection.execute(
            sa.text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid='saas_oidc_session_fences'::regclass"
            )
        ).one()
        assert tuple(row) == (True, True)
    for role in ("saas_app", "saas_governance", "saas_platform_app"):
        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {role}")
            with pytest.raises(DBAPIError):
                connection.exec_driver_sql("SELECT * FROM saas_oidc_session_fences")
    user = (
        IdentityManagementService(sessions)
        .resolve_verified_login(
            VerifiedIdentityAssertion(
                provider="casdoor",
                issuer="https://auth.example.test",
                subject="trusted-sub",
                email="trusted@example.test",
                email_verified=True,
            )
        )
        .user_id
    )
    assert user is not None
    now = datetime.now(timezone.utc)
    with pytest.raises(LifecycleError, match="connection is unavailable"):
        MembershipLifecycleService(sessions).issue_auth_session(
            user_id=user,
            authn_method="oidc:casdoor",
            expires_at=now + timedelta(hours=1),
            external_identity=ExternalSessionIdentity(
                "casdoor", "https://auth.example.test", "forged-sub", now
            ),
        )


@pytest.mark.parametrize("retained", ["empty", "fence", "session", "oidc"])
def test_non_bypass_schema_owner_cannot_drop_retained_federated_state(
    postgres_federation: tuple[sa.Engine, sessionmaker[Session]], retained: str
) -> None:
    engine, sessions = postgres_federation
    now = datetime.now(timezone.utc)
    if retained == "fence":
        FederatedSessionService(sessions).revoke(
            VerifiedLogoutEvent(
                "casdoor", "https://auth.example.test", "retained", now, "s", None
            ),
            now=now,
        )
    elif retained == "session":
        user = IdentityManagementService(sessions).resolve_verified_login(
            VerifiedIdentityAssertion(
                provider="casdoor",
                issuer="https://auth.example.test",
                subject="retained-user",
                email=None,
                email_verified=False,
            )
        )
        assert user.user_id is not None
        MembershipLifecycleService(sessions).issue_auth_session(
            user_id=user.user_id,
            authn_method="oidc:casdoor",
            expires_at=now + timedelta(hours=1),
            external_identity=ExternalSessionIdentity(
                "casdoor", "https://auth.example.test", "retained-user", now
            ),
        )
        with engine.begin() as connection:
            connection.exec_driver_sql("DELETE FROM saas_oidc_session_fences")
    elif retained == "oidc":
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO saas_oidc_login_transactions "
                    "(id,provider,state_hash,browser_binding_hash,nonce_hash,code_verifier_ciphertext,"
                    "purpose,status,expires_at) VALUES "
                    "(:id,'casdoor',:state,:binding,:nonce,'retained','reauth','pending',:expiry)"
                ),
                {
                    "id": uuid4(),
                    "state": "a" * 64,
                    "binding": "b" * 64,
                    "nonce": "c" * 64,
                    "expiry": now + timedelta(minutes=5),
                },
            )

    owner = "federated_migration_" + uuid4().hex
    with engine.begin() as connection:
        original_owner = connection.scalar(sa.text("SELECT current_user"))
        connection.exec_driver_sql(f"CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOBYPASSRLS")
        connection.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {owner}")
        # Schema owners can reference tables used by existing RLS predicates.
        connection.exec_driver_sql(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {owner}")
        connection.exec_driver_sql(f"GRANT SELECT, UPDATE ON saas_alembic_version TO {owner}")
        for table in (
            "saas_auth_sessions",
            "saas_oidc_session_fences",
            "saas_oidc_login_transactions",
        ):
            connection.exec_driver_sql(f"ALTER TABLE {table} OWNER TO {owner}")
    try:

        def downgrade() -> None:
            with engine.begin() as connection:
                connection.exec_driver_sql(f"SET LOCAL ROLE {owner}")
                assert not connection.scalar(
                    sa.text(
                        "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname=current_user"
                    )
                )
                config = Config(
                    Path(__file__).resolve().parents[2] / "saas/control_plane/alembic.ini"
                )
                config.attributes["connection"] = connection
                command.downgrade(config, "cd1a00000001")

        if retained == "empty":
            downgrade()
        else:
            with pytest.raises(RuntimeError, match="application-only rollback"):
                downgrade()
            with engine.connect() as connection:
                assert connection.scalar(
                    sa.text("SELECT version_num FROM saas_alembic_version")
                ) == ("cd1c00000001")
                table = (
                    "saas_oidc_login_transactions"
                    if retained == "oidc"
                    else "saas_oidc_session_fences"
                    if retained == "fence"
                    else "saas_auth_sessions"
                )
                assert connection.scalar(sa.text(f"SELECT count(*) FROM {table}")) > 0
    finally:
        with engine.begin() as connection:
            for table in (
                "saas_auth_sessions",
                "saas_oidc_session_fences",
                "saas_oidc_login_transactions",
            ):
                connection.exec_driver_sql(
                    f'ALTER TABLE IF EXISTS {table} OWNER TO "{original_owner}"'
                )
            connection.exec_driver_sql(f"DROP OWNED BY {owner}")
            connection.exec_driver_sql(f"DROP ROLE {owner}")


def test_authenticator_links_reviewed_conflict_and_audits_it_atomically(
    postgres_federation: tuple[sa.Engine, sessionmaker[Session]],
) -> None:
    engine, sessions = postgres_federation
    identities = IdentityManagementService(sessions)
    primary = VerifiedIdentityAssertion(
        "existing", "https://existing.example.test", "owner", "owner@example.test", True
    )
    owner = identities.resolve_verified_login(primary).user_id
    assert owner is not None
    secondary = VerifiedIdentityAssertion(
        "casdoor", "https://auth.example.test", "secondary", "owner@example.test", True
    )
    conflict = identities.resolve_verified_login(secondary)
    assert conflict.user_id is None and conflict.conflict_id is not None
    connection = identities.link_identity(
        user_id=owner, assertion=secondary, idempotency_key="explicit-reviewed-link"
    )
    assert (
        identities.link_identity(
            user_id=owner, assertion=secondary, idempotency_key="explicit-reviewed-link"
        )
        == connection
    )
    with sessions() as db:
        row = db.get(IdentityConflict, conflict.conflict_id)
        assert row is not None and row.status == "approved" and row.resolved_by == owner
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == "identity.conflict.resolved")
            )
            == 1
        )
    ambiguous = VerifiedIdentityAssertion(
        "casdoor", "https://auth.example.test", "ambiguous", "owner@example.test", True
    )
    pending = identities.resolve_verified_login(ambiguous)
    with engine.begin() as connection:
        connection.execute(
            sa.update(IdentityConflict)
            .where(IdentityConflict.id == pending.conflict_id)
            .values(candidate_user_id=None)
        )
    with pytest.raises(LifecycleError, match="requires platform review"):
        identities.link_identity(
            user_id=owner, assertion=ambiguous, idempotency_key="ambiguous-reviewed-link"
        )
    assert len(identities.list_identities(owner)) == 2
