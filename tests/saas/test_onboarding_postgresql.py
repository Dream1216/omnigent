from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.onboarding import (
    OnboardingError,
    OnboardingPlan,
    OnboardingPolicy,
    SelfServiceOnboardingService,
    TenantOnboardingCoordinator,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding_http import _http_error
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES

_EMAIL_EVENT = "onboarding.email_verification.requested"
_TENANT_EVENT = "onboarding.tenant.requested"


class _AllowAllRateLimiter:
    def require(self, *, action: str, subject_hash: str, now: datetime) -> None:
        del action, subject_hash, now


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for P0 onboarding acceptance")
    return value


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


@pytest.fixture(scope="module")
def postgresql_engine() -> Iterator[Engine]:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
    try:
        yield engine
    finally:
        engine.dispose()


def _role_sessions(engine: Engine, role: str) -> sessionmaker[Session]:
    sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(sessions, "after_begin")
    def _set_role(
        _session: Session,
        _transaction: object,
        connection: sa.Connection,
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return sessions


def _policy() -> OnboardingPolicy:
    return OnboardingPolicy(
        plans=(
            OnboardingPlan(
                key="starter",
                policy_revision="starter-p0-postgresql",
                trial_days=14,
            ),
        ),
        home_regions=frozenset({"cn-east-1"}),
        reserved_slugs=frozenset({"admin", "platform"}),
        verification_ttl=timedelta(minutes=30),
    )


def _set_guc(connection: sa.Connection, name: str, value: UUID | str) -> None:
    connection.execute(
        sa.text("SELECT set_config(:name, :value, true)"),
        {"name": name, "value": str(value)},
    )


def _assert_rls_denied(error: DBAPIError) -> None:
    assert getattr(error.orig, "sqlstate", None) == "42501"


def _insert_registration_probe(
    connection: sa.Connection,
    *,
    suffix: str,
    registration_id: UUID,
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_self_service_registrations ("
            "id, email_normalized, email_hash, display_name, tenant_name, tenant_slug, "
            "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
            "home_region, status, challenge_generation, expires_at, user_id, tenant_id, "
            "space_id, subscription_id, runtime_partition_id, onboarding_id, "
            "idempotency_key, request_hash, version, created_at, updated_at"
            ") VALUES ("
            ":id, :email, :email_hash, 'Denied Probe', 'Denied Tenant', :tenant_slug, "
            "'Default Space', 'default', 'starter', 'starter-p0-postgresql', "
            "'cn-east-1', 'pending_verification', 1, now() + interval '30 minutes', "
            ":user_id, :tenant_id, :space_id, :subscription_id, :partition_id, "
            ":onboarding_id, :idempotency_key, :request_hash, 1, now(), now())"
        ),
        {
            "id": registration_id,
            "email": f"denied-{suffix}@example.test",
            "email_hash": "a" * 64,
            "tenant_slug": f"denied-{suffix}",
            "user_id": uuid4(),
            "tenant_id": uuid4(),
            "space_id": uuid4(),
            "subscription_id": uuid4(),
            "partition_id": uuid4(),
            "onboarding_id": uuid4(),
            "idempotency_key": "b" * 64,
            "request_hash": "c" * 64,
        },
    )


def test_onboarding_roles_and_all_107_control_plane_tables_are_force_rls(
    postgresql_engine: Engine,
) -> None:
    with postgresql_engine.begin() as connection:
        role_facts = connection.execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls FROM pg_roles "
                "WHERE rolname IN ('saas_registration', 'saas_onboarding') "
                "ORDER BY rolname"
            )
        ).all()
        assert role_facts == [
            ("saas_onboarding", False, False, False, False, False, False),
            ("saas_registration", False, False, False, False, False, False),
        ]

        protected = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relrowsecurity "
                    "AND relforcerowsecurity AND relname = ANY(:table_names)"
                ),
                {"table_names": sorted(CONTROL_PLANE_RLS_TABLES)},
            ).scalars()
        )
        assert len(CONTROL_PLANE_RLS_TABLES) == 107
        assert protected == CONTROL_PLANE_RLS_TABLES

        email_index = connection.execute(
            sa.text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE tablename = 'saas_self_service_registrations' "
                "AND indexname = 'uq_open_self_service_email'"
            )
        ).scalar_one()
        assert "pending_verification" in email_index
        assert "suppressed" in email_index
        assert "verified" in email_index


@pytest.mark.parametrize("context", ["missing", "wrong"])
def test_registration_insert_requires_exact_server_generated_gucs(
    postgresql_engine: Engine,
    context: str,
) -> None:
    suffix = uuid4().hex[:12]
    registration_id = uuid4()
    with pytest.raises(DBAPIError) as denied:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_registration")
            if context == "wrong":
                _set_guc(connection, "app.registration_id", uuid4())
                _set_guc(connection, "app.registration_email_hash", "a" * 64)
                _set_guc(connection, "app.registration_idempotency_key", "b" * 64)
            _insert_registration_probe(
                connection,
                suffix=suffix,
                registration_id=registration_id,
            )
    _assert_rls_denied(denied.value)


def test_real_postgresql_registration_verify_and_onboarding_e2e(
    postgresql_engine: Engine,
) -> None:
    suffix = uuid4().hex[:12]
    now = datetime(2026, 8, 10, 2, 0, tzinfo=timezone.utc)
    policy = _policy()
    envelopes = VerificationEnvelopeKeyring(
        active_key_id="p0-postgresql-v1",
        keys={"p0-postgresql-v1": b"p" * 32},
    )
    registrations = SelfServiceOnboardingService(
        _role_sessions(postgresql_engine, "saas_registration"),
        policy=policy,
        envelope_keyring=envelopes,
        rate_limiter=_AllowAllRateLimiter(),
    )
    coordinator = TenantOnboardingCoordinator(
        _role_sessions(postgresql_engine, "saas_onboarding"),
        policy=policy,
    )
    request = {
        "email": f"owner-{suffix}@example.test",
        "display_name": "PostgreSQL Owner",
        "tenant_name": f"PostgreSQL Tenant {suffix}",
        "tenant_slug": f"pg-{suffix}",
        "default_space_name": "Default Space",
        "default_space_slug": "default",
        "plan_key": "starter",
        "home_region": "cn-east-1",
        "idempotency_key": f"registration-{suffix}",
    }

    accepted = registrations.request_registration(**request, now=now)
    assert accepted.replayed is False
    replay = registrations.request_registration(**request, now=now + timedelta(seconds=1))
    assert replay.registration_id == accepted.registration_id
    assert replay.replayed is True

    with pytest.raises(OnboardingError) as conflict:
        registrations.request_registration(
            **{**request, "tenant_name": f"Drifted Tenant {suffix}"},
            now=now + timedelta(seconds=2),
        )
    assert conflict.value.code == "idempotency_conflict"
    assert _http_error(conflict.value).status_code == 409

    for column, value in (
        ("email_normalized", f"rewritten-{suffix}@example.test"),
        ("tenant_id", str(uuid4())),
    ):
        with pytest.raises(DBAPIError) as immutable:
            with postgresql_engine.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE saas_registration")
                _set_guc(connection, "app.registration_id", accepted.registration_id)
                connection.execute(
                    sa.text(
                        f"UPDATE saas_self_service_registrations "
                        f"SET {column} = :value WHERE id = :registration_id"
                    ),
                    {"value": value, "registration_id": accepted.registration_id},
                )
        _assert_rls_denied(immutable.value)

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        email_event = connection.execute(
            sa.text(
                "SELECT id, payload FROM saas_control_plane_outbox "
                "WHERE aggregate_type = 'self_service_registration' "
                "AND aggregate_key = :registration_id AND event_type = :event_type"
            ),
            {
                "registration_id": str(accepted.registration_id),
                "event_type": _EMAIL_EVENT,
            },
        ).one()
    message = envelopes.open(event_id=email_event.id, payload=email_event.payload)

    requested = registrations.verify_and_request_onboarding(
        registration_id=accepted.registration_id,
        verification_token=message.verification_token,
        password="correct-horse-battery-staple",
        idempotency_key=f"verify-{suffix}",
        now=now + timedelta(minutes=1),
    )
    assert requested.replayed is False

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        tenant_event_id = connection.execute(
            sa.text(
                "SELECT id FROM saas_control_plane_outbox "
                "WHERE aggregate_type = 'tenant_onboarding' "
                "AND aggregate_key = :onboarding_id AND event_type = :event_type"
            ),
            {
                "onboarding_id": str(requested.onboarding_id),
                "event_type": _TENANT_EVENT,
            },
        ).scalar_one()

    started = coordinator.start(
        registration_id=accepted.registration_id,
        idempotency_key=str(tenant_event_id),
        now=now + timedelta(minutes=2),
    )
    assert started.onboarding_id == requested.onboarding_id
    assert started.status == "tenant_created"
    assert started.replayed is False

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        state = connection.execute(
            sa.text(
                "SELECT tenant.status, tenant.lifecycle_version, space.status, "
                "tenant_member.role, tenant_member.status, tenant_member.version, "
                "space_member.role, space_member.status, space_member.version, "
                "saga.status, saga.trial_started_at, saga.trial_ends_at "
                "FROM saas_tenant_onboardings saga "
                "JOIN saas_tenants tenant ON tenant.id = saga.tenant_id "
                "JOIN saas_spaces space ON space.id = saga.space_id "
                "JOIN saas_tenant_memberships tenant_member "
                "ON tenant_member.tenant_id = saga.tenant_id "
                "AND tenant_member.user_id = saga.user_id "
                "JOIN saas_space_memberships space_member "
                "ON space_member.tenant_id = saga.tenant_id "
                "AND space_member.space_id = saga.space_id "
                "AND space_member.user_id = saga.user_id "
                "WHERE saga.id = :onboarding_id"
            ),
            {"onboarding_id": requested.onboarding_id},
        ).one()
        assert state == (
            "provisioning",
            1,
            "suspended",
            "owner",
            "active",
            1,
            "owner",
            "active",
            1,
            "tenant_created",
            None,
            None,
        )
        event_id = connection.execute(
            sa.text(
                "SELECT id FROM saas_self_service_events "
                "WHERE aggregate_type = 'tenant_onboarding' "
                "AND aggregate_id = :onboarding_id"
            ),
            {"onboarding_id": requested.onboarding_id},
        ).scalar_one()

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding")
        _set_guc(connection, "app.registration_id", accepted.registration_id)
        _set_guc(connection, "app.onboarding_id", requested.onboarding_id)
        _set_guc(connection, "app.actor_id", requested.user_id)
        _set_guc(connection, "app.tenant_id", uuid4())
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_tenant_onboardings WHERE id = :onboarding_id"),
                {"onboarding_id": requested.onboarding_id},
            ).scalar_one()
            == 0
        )

    with pytest.raises(DBAPIError) as cross_scope:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding")
            _set_guc(connection, "app.registration_id", accepted.registration_id)
            _set_guc(connection, "app.onboarding_id", requested.onboarding_id)
            _set_guc(connection, "app.actor_id", requested.user_id)
            _set_guc(connection, "app.tenant_id", requested.tenant_id)
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenants "
                    "(id, slug, name, status, plan, home_region, lifecycle_version) "
                    "VALUES (:id, :slug, 'Cross Scope', 'provisioning', 'starter', "
                    "'cn-east-1', 1)"
                ),
                {"id": uuid4(), "slug": f"cross-{suffix}"},
            )
    _assert_rls_denied(cross_scope.value)

    for statement in (
        "UPDATE saas_self_service_events SET event_type = 'mutated' WHERE id = :event_id",
        "DELETE FROM saas_self_service_events WHERE id = :event_id",
    ):
        with pytest.raises(DBAPIError, match="self-service events are immutable"):
            with postgresql_engine.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
                connection.execute(sa.text(statement), {"event_id": event_id})
