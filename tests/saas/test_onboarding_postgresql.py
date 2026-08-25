from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.execution import ExecutionControlPlane, ExecutionRevisionSet
from saas.control_plane.onboarding import (
    OnboardingError,
    OnboardingPlan,
    OnboardingPolicy,
    SelfServiceOnboardingService,
    TenantOnboardingCoordinator,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding_http import _http_error
from saas.control_plane.onboarding_status import (
    OnboardingStatusError,
    OnboardingStatusService,
)
from saas.control_plane.onboarding_workflow import (
    OnboardingScope,
    RuntimePartitionAllocation,
    RuntimePartitionTarget,
    RuntimeProjectAllocation,
    RuntimeProjectTarget,
    RuntimeProviderBindingSnapshot,
    TenantOnboardingWorkflow,
)
from saas.control_plane.outbox import OutboxDispatcher, OutboxPublishError
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from saas.control_plane.runtime_provider import ProductionRuntimePartitionAdapter
from saas.onboarding_composition import (
    CommittedRunAdmissionObserver,
    OnboardingDatabaseAuthority,
    OnboardingFirstRunAdmissionAdapter,
    TenantOnboardingDependencies,
    verify_onboarding_database_authority,
)

_EMAIL_EVENT = "onboarding.email_verification.requested"
_TENANT_EVENT = "onboarding.tenant.requested"


class _AllowAllRateLimiter:
    def require(self, *, action: str, subject_hash: str, now: datetime) -> None:
        del action, subject_hash, now


@dataclass(slots=True)
class _PostgresqlRuntime:
    placement_id: UUID
    allocation_failures_remaining: int = 0
    partition_compensations: int = 0

    def binding_snapshot(self, placement_id: UUID) -> RuntimeProviderBindingSnapshot:
        assert placement_id == self.placement_id
        return RuntimeProviderBindingSnapshot(
            provider_type="postgresql-test-runtime",
            binding_revision="postgresql-test-binding-v1",
            binding_hash=sha256(f"postgresql-binding:{placement_id}".encode()).hexdigest(),
        )

    def allocate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> RuntimePartitionAllocation:
        assert target.placement_id == self.placement_id
        if self.allocation_failures_remaining:
            self.allocation_failures_remaining -= 1
            raise RuntimeError("injected PostgreSQL runtime allocation failure")
        return RuntimePartitionAllocation(
            runtime_version="0.11.0.dev0",
            physical_partition_key=str(int(target.runtime_partition_id.hex[:12], 16) or 1),
            placement_generation=1,
            source_revision="14df304a8e958da36b8a606a2c825e3a6642247e",
            adapter_contract_version="0.2.0",
            runtime_user_key=f"user-{target.user_id.hex}",
            receipt_hash=sha256(idempotency_key.encode()).hexdigest(),
        )

    def provision_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> RuntimeProjectAllocation:
        assert target.partition.placement_id == self.placement_id
        return RuntimeProjectAllocation(
            runtime_resource_id=f"project-{target.project_id}",
            receipt_hash=sha256(idempotency_key.encode()).hexdigest(),
        )

    def compensate_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> None:
        del target, idempotency_key

    def compensate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> None:
        del target, idempotency_key
        self.partition_compensations += 1


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


@pytest.fixture
def isolated_onboarding_engine(isolated_postgres_url: str) -> Iterator[Engine]:
    """Give placement-selection tests a database with no historical candidates."""

    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
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


@contextmanager
def _production_status_service(engine: Engine) -> Iterator[OnboardingStatusService]:
    suffix = uuid4().hex[:12]
    login = f"onboarding_status_{suffix}"
    password = f"Onboarding-Status-{uuid4().hex}"
    with engine.begin() as connection:
        quoted_login = connection.dialect.identifier_preparer.quote(login)
        connection.exec_driver_sql(
            f"CREATE ROLE {quoted_login} LOGIN INHERIT NOSUPERUSER NOBYPASSRLS "
            f"PASSWORD '{password}'"
        )
        connection.exec_driver_sql(f"GRANT saas_onboarding_status TO {quoted_login}")
        connection.exec_driver_sql(f"ALTER ROLE {quoted_login} SET search_path = public")
    status_engine = sa.create_engine(
        engine.url.set(username=login, password=password),
        pool_pre_ping=True,
    )
    try:
        yield OnboardingStatusService(sessionmaker(status_engine, expire_on_commit=False))
    finally:
        status_engine.dispose()
        with engine.begin() as connection:
            quoted_login = connection.dialect.identifier_preparer.quote(login)
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_login}")


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


def _create_started_scope(
    engine: Engine,
    *,
    suffix: str,
    now: datetime,
) -> tuple[OnboardingScope, sessionmaker[Session]]:
    policy = _policy()
    envelopes = VerificationEnvelopeKeyring(
        active_key_id=f"scope-{suffix}",
        keys={f"scope-{suffix}": b"s" * 32},
    )
    registration_sessions = _role_sessions(engine, "saas_registration")
    onboarding_sessions = _role_sessions(engine, "saas_onboarding")
    registrations = SelfServiceOnboardingService(
        registration_sessions,
        policy=policy,
        envelope_keyring=envelopes,
        rate_limiter=_AllowAllRateLimiter(),
    )
    accepted = registrations.request_registration(
        email=f"scope-{suffix}@example.test",
        display_name="Scoped Owner",
        tenant_name=f"Scoped Tenant {suffix}",
        tenant_slug=f"scope-{suffix}",
        default_space_name="Default Space",
        default_space_slug="default",
        plan_key="starter",
        home_region="cn-east-1",
        idempotency_key=f"scope-registration-{suffix}",
        now=now,
    )
    with engine.begin() as connection:
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
        idempotency_key=f"scope-verify-{suffix}",
        now=now + timedelta(minutes=1),
    )
    with engine.begin() as connection:
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
    started = TenantOnboardingCoordinator(onboarding_sessions, policy=policy).start(
        registration_id=accepted.registration_id,
        idempotency_key=str(tenant_event_id),
        now=now + timedelta(minutes=2),
    )
    return (
        OnboardingScope(
            onboarding_id=started.onboarding_id,
            registration_id=accepted.registration_id,
            actor_id=requested.user_id,
            tenant_id=requested.tenant_id,
        ),
        onboarding_sessions,
    )


def _assert_rls_denied(error: DBAPIError) -> None:
    assert getattr(error.orig, "sqlstate", None) == "42501"


class _DiscardingEmailSender:
    def send_verification(self, **_kwargs: object) -> None:
        return None


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
            "space_id, subscription_id, pricing_snapshot_id, entitlement_id, "
            "runtime_partition_id, default_project_id, runtime_binding_id, "
            "plan_snapshot, plan_snapshot_hash, onboarding_id, "
            "idempotency_key, request_hash, version, created_at, updated_at"
            ") VALUES ("
            ":id, :email, :email_hash, 'Denied Probe', 'Denied Tenant', :tenant_slug, "
            "'Default Space', 'default', 'starter', 'starter-p0-postgresql', "
            "'cn-east-1', 'pending_verification', 1, now() + interval '30 minutes', "
            ":user_id, :tenant_id, :space_id, :subscription_id, :pricing_snapshot_id, "
            ":entitlement_id, :partition_id, :default_project_id, :runtime_binding_id, "
            "CAST(:plan_snapshot AS jsonb), :plan_snapshot_hash, :onboarding_id, "
            ":idempotency_key, :request_hash, 1, now(), now())"
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
            "pricing_snapshot_id": uuid4(),
            "entitlement_id": uuid4(),
            "partition_id": uuid4(),
            "default_project_id": uuid4(),
            "runtime_binding_id": uuid4(),
            "plan_snapshot": '{"plan_key":"starter"}',
            "plan_snapshot_hash": "e" * 64,
            "onboarding_id": uuid4(),
            "idempotency_key": "b" * 64,
            "request_hash": "c" * 64,
        },
    )


def test_onboarding_roles_and_all_109_control_plane_tables_are_force_rls(
    postgresql_engine: Engine,
) -> None:
    with postgresql_engine.begin() as connection:
        role_facts = connection.execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls FROM pg_roles "
                "WHERE rolname IN ("
                "'saas_registration', 'saas_onboarding', 'saas_onboarding_status') "
                "ORDER BY rolname"
            )
        ).all()
        assert role_facts == [
            ("saas_onboarding", False, False, False, False, False, False),
            ("saas_onboarding_status", False, False, False, False, False, False),
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
        assert len(CONTROL_PLANE_RLS_TABLES) == 109
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
        producer_policy = connection.execute(
            sa.text(
                "SELECT policy.polpermissive, policy.polcmd, policy.polroles "
                "FROM pg_policy policy JOIN pg_class relation "
                "ON relation.oid = policy.polrelid "
                "WHERE relation.relname = 'saas_control_plane_outbox' "
                "AND policy.polname = 'rls_outbox_producer_initial_state'"
            )
        ).one()
        assert producer_policy == (False, "a", [0])
        assert not connection.execute(
            sa.text(
                "SELECT has_column_privilege('saas_app', "
                "'saas_tenant_onboardings', 'status', 'SELECT')"
            )
        ).scalar_one()
        for role in ("saas_registration", "saas_onboarding"):
            for column in (
                "last_error",
                "last_error_code",
                "last_error_digest",
                "quarantined_at",
            ):
                assert not connection.execute(
                    sa.text(
                        "SELECT has_column_privilege(:role, "
                        "'saas_control_plane_outbox', :column, 'INSERT')"
                    ),
                    {"role": role, "column": column},
                ).scalar_one()
        allowed_dispatcher_updates = {
            "attempt_count",
            "available_at",
            "claimed_at",
            "claim_token",
            "last_error_code",
            "last_error_digest",
            "published_at",
            "quarantined_at",
        }
        for column in {
            row.column_name
            for row in connection.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'saas_control_plane_outbox'"
                )
            )
        }:
            can_update = connection.execute(
                sa.text(
                    "SELECT has_column_privilege('saas_dispatcher', "
                    "'saas_control_plane_outbox', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
            assert can_update is (column in allowed_dispatcher_updates)


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


def test_registration_cannot_fabricate_outbox_delivery_state(
    postgresql_engine: Engine,
) -> None:
    suffix = uuid4().hex[:12]
    registration_id = uuid4()
    with pytest.raises(DBAPIError) as denied:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_registration")
            _set_guc(connection, "app.registration_id", registration_id)
            _set_guc(connection, "app.registration_email_hash", "a" * 64)
            _set_guc(connection, "app.registration_idempotency_key", "b" * 64)
            _insert_registration_probe(
                connection,
                suffix=suffix,
                registration_id=registration_id,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox ("
                    "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at, "
                    "claimed_at, claim_token, published_at) VALUES ("
                    ":id, NULL, 'self_service_registration', :aggregate_key, "
                    "'onboarding.email_verification.requested', CAST('{}' AS jsonb), "
                    ":idempotency_key, :request_hash, 0, NULL, NULL, NULL, now())"
                ),
                {
                    "id": uuid4(),
                    "aggregate_key": str(registration_id),
                    "idempotency_key": f"forged-delivery-{registration_id}",
                    "request_hash": "d" * 64,
                },
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


def test_real_postgresql_customer_status_is_actor_owned_and_content_blind(
    postgresql_engine: Engine,
) -> None:
    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    first_scope, _ = _create_started_scope(
        postgresql_engine,
        suffix=f"status-a-{uuid4().hex[:8]}",
        now=now,
    )
    second_scope, _ = _create_started_scope(
        postgresql_engine,
        suffix=f"status-b-{uuid4().hex[:8]}",
        now=now + timedelta(seconds=1),
    )
    with _production_status_service(postgresql_engine) as customer_status:
        first = customer_status.for_actor(first_scope.actor_id)
        second = customer_status.for_actor(second_scope.actor_id)
        assert (first.state, first.stage) == ("provisioning", "billing")
        assert (second.state, second.stage) == ("provisioning", "billing")
        assert first.tenant_id is None and second.tenant_id is None

        with pytest.raises(OnboardingStatusError) as unavailable:
            customer_status.for_actor(uuid4())
        assert unavailable.value.code == "onboarding_status_unavailable"

        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding_status")
            _set_guc(connection, "app.actor_id", first_scope.actor_id)
            visible_ids = set(
                connection.execute(
                    sa.text("SELECT id FROM saas_tenant_onboardings ORDER BY id")
                ).scalars()
            )
            assert visible_ids == {first_scope.onboarding_id}
            assert second_scope.onboarding_id not in visible_ids

        with pytest.raises(DBAPIError) as content_denied:
            with postgresql_engine.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding_status")
                _set_guc(connection, "app.actor_id", first_scope.actor_id)
                connection.execute(
                    sa.text(
                        "SELECT last_error_detail FROM saas_tenant_onboardings "
                        "WHERE id = :onboarding_id"
                    ),
                    {"onboarding_id": first_scope.onboarding_id},
                ).all()
        _assert_rls_denied(content_denied.value)

        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_tenant_memberships SET status = 'removed', "
                    "version = version + 1 WHERE tenant_id = :tenant_id "
                    "AND user_id = :user_id"
                ),
                {"tenant_id": first_scope.tenant_id, "user_id": first_scope.actor_id},
            )
        with pytest.raises(OnboardingStatusError) as removed:
            customer_status.for_actor(first_scope.actor_id)
        assert removed.value.code == "onboarding_status_unavailable"


def test_real_postgresql_dispatcher_quarantines_poison_with_content_blind_receipt(
    postgresql_engine: Engine,
) -> None:
    event_id = uuid4()
    dispatched_at = datetime.now(timezone.utc)
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox ("
                "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, available_at, created_at"
                ") VALUES ("
                ":id, NULL, 'acceptance', :aggregate_key, 'acceptance.poison', "
                "CAST('{}' AS jsonb), :idempotency_key, :request_hash, 0, "
                ":created_at, :created_at)"
            ),
            {
                "id": event_id,
                "aggregate_key": str(event_id),
                "idempotency_key": f"postgres-quarantine-{event_id}",
                "request_hash": sha256(event_id.bytes).hexdigest(),
                "created_at": datetime(2020, 1, 1, tzinfo=timezone.utc),
            },
        )

    class _PoisonPublisher:
        def publish(self, **_event: object) -> None:
            raise OutboxPublishError(
                "acceptance_envelope_invalid",
                retryable=False,
                pre_side_effect=True,
            )

    result = OutboxDispatcher(
        _role_sessions(postgresql_engine, "saas_dispatcher"),
        _PoisonPublisher(),
    ).dispatch_once(batch_size=1, now=dispatched_at)
    assert (result.claimed, result.published, result.failed, result.quarantined) == (
        1,
        0,
        1,
        1,
    )

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
        source = connection.execute(
            sa.text(
                "SELECT published_at, quarantined_at, last_error, last_error_code, "
                "last_error_digest, available_at, claimed_at, claim_token "
                "FROM saas_control_plane_outbox WHERE id = :id"
            ),
            {"id": event_id},
        ).one()
        receipt = connection.execute(
            sa.text(
                "SELECT source_event_id, source_request_hash, source_attempt_count, "
                "action, error_code, error_digest, sequence, previous_hash, event_hash "
                "FROM saas_outbox_quarantine_events WHERE source_event_id = :id"
            ),
            {"id": event_id},
        ).one()
        assert source.published_at is None
        assert source.quarantined_at == dispatched_at
        assert source.available_at is None
        assert source.claimed_at is None
        assert source.claim_token is None
        assert source.last_error is None
        assert source.last_error_code == "acceptance_envelope_invalid"
        assert receipt.source_event_id == event_id
        assert receipt.source_attempt_count == 1
        assert receipt.action == "quarantined"
        assert receipt.error_code == source.last_error_code
        assert receipt.error_digest == source.last_error_digest
        assert receipt.sequence == 1
        assert receipt.previous_hash == "0" * 64
        assert len(receipt.source_request_hash) == 64
        assert len(receipt.event_hash) == 64

    with pytest.raises(DBAPIError) as dispatcher_mutation:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
            connection.execute(
                sa.text(
                    "UPDATE saas_outbox_quarantine_events SET error_code = 'mutated' "
                    "WHERE source_event_id = :id"
                ),
                {"id": event_id},
            )
    _assert_rls_denied(dispatcher_mutation.value)

    with postgresql_engine.begin() as connection:
        columns = {
            row.attname
            for row in connection.execute(
                sa.text(
                    "SELECT attribute.attname FROM pg_attribute attribute "
                    "JOIN pg_class relation ON relation.oid = attribute.attrelid "
                    "WHERE relation.relname = 'saas_outbox_quarantine_events' "
                    "AND attribute.attnum > 0 AND NOT attribute.attisdropped"
                )
            )
        }
        assert "payload" not in columns
        assert "aggregate_key" not in columns


def test_real_postgresql_dispatcher_cannot_forge_or_skip_quarantine_receipt(
    postgresql_engine: Engine,
) -> None:
    direct_id, forged_id = uuid4(), uuid4()
    future = datetime.now(timezone.utc) + timedelta(days=365)
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        for event_id in (direct_id, forged_id):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox ("
                    "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at"
                    ") VALUES ("
                    ":id, NULL, 'acceptance', :aggregate_key, 'acceptance.future', "
                    "CAST('{}' AS jsonb), :idempotency_key, :request_hash, 0, :future)"
                ),
                {
                    "id": event_id,
                    "aggregate_key": str(event_id),
                    "idempotency_key": f"postgres-quarantine-negative-{event_id}",
                    "request_hash": sha256(event_id.bytes).hexdigest(),
                    "future": future,
                },
            )

    with pytest.raises(DBAPIError) as immutable_source:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET payload = CAST(:payload AS jsonb) "
                    "WHERE id = :id"
                ),
                {"id": direct_id, "payload": '{"x":1}'},
            )
    _assert_rls_denied(immutable_source.value)

    terminal_at = datetime.now(timezone.utc)
    terminal_digest = sha256(b"direct terminal without receipt").hexdigest()
    with pytest.raises(DBAPIError, match="requires one exact receipt") as missing_receipt:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET attempt_count = 1, "
                    "available_at = NULL, last_error_code = 'acceptance_invalid', "
                    "last_error_digest = :digest, quarantined_at = :terminal_at "
                    "WHERE id = :id"
                ),
                {"id": direct_id, "digest": terminal_digest, "terminal_at": terminal_at},
            )
    assert getattr(missing_receipt.value.orig, "sqlstate", None) == "23514"

    forged_at = terminal_at + timedelta(seconds=1)
    forged_digest = sha256(b"forged mismatched receipt").hexdigest()
    with pytest.raises(DBAPIError) as forged_receipt:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET attempt_count = 1, "
                    "available_at = NULL, last_error_code = 'acceptance_invalid', "
                    "last_error_digest = :digest, quarantined_at = :terminal_at "
                    "WHERE id = :id"
                ),
                {"id": forged_id, "digest": forged_digest, "terminal_at": forged_at},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_outbox_quarantine_events ("
                    "id, source_event_id, tenant_id, source_request_hash, "
                    "source_attempt_count, action, error_code, error_digest, sequence, "
                    "previous_hash, event_hash, created_at) VALUES ("
                    ":receipt_id, :source_id, NULL, :request_hash, 2, 'quarantined', "
                    "'acceptance_invalid', :digest, 1, :previous_hash, :event_hash, "
                    ":terminal_at)"
                ),
                {
                    "receipt_id": uuid4(),
                    "source_id": forged_id,
                    "request_hash": sha256(forged_id.bytes).hexdigest(),
                    "digest": forged_digest,
                    "previous_hash": "0" * 64,
                    "event_hash": sha256(b"forged receipt").hexdigest(),
                    "terminal_at": forged_at,
                },
            )
    _assert_rls_denied(forged_receipt.value)


def test_real_postgresql_quarantine_receipt_cannot_create_pg_temp_shadow(
    postgresql_engine: Engine,
) -> None:
    event_id = uuid4()
    terminal_at = datetime.now(timezone.utc)
    request_hash = sha256(event_id.bytes).hexdigest()
    terminal_digest = sha256(b"pg-temp-shadow-receipt").hexdigest()
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox ("
                "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, available_at"
                ") VALUES ("
                ":id, NULL, 'acceptance', :aggregate_key, 'acceptance.temp_shadow', "
                "CAST('{}' AS jsonb), :idempotency_key, :request_hash, 0, NULL)"
            ),
            {
                "id": event_id,
                "aggregate_key": str(event_id),
                "idempotency_key": f"postgres-quarantine-shadow-{event_id}",
                "request_hash": request_hash,
            },
        )

    with pytest.raises(
        DBAPIError, match="permission denied to create temporary tables"
    ) as rejected:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
            connection.exec_driver_sql(
                "CREATE TEMP TABLE saas_outbox_quarantine_events ("
                "source_event_id uuid, tenant_id uuid, source_request_hash varchar(64), "
                "source_attempt_count integer, action varchar(32), error_code varchar(128), "
                "error_digest varchar(64), sequence bigint, previous_hash varchar(64), "
                "created_at timestamptz) ON COMMIT DROP"
            )
            connection.execute(
                sa.text(
                    "INSERT INTO pg_temp.saas_outbox_quarantine_events VALUES ("
                    ":source_event_id, NULL, :request_hash, 1, 'quarantined', "
                    "'acceptance_invalid', :error_digest, 1, :previous_hash, :created_at)"
                ),
                {
                    "source_event_id": event_id,
                    "request_hash": request_hash,
                    "error_digest": terminal_digest,
                    "previous_hash": "0" * 64,
                    "created_at": terminal_at,
                },
            )
            connection.execute(
                sa.text(
                    "UPDATE public.saas_control_plane_outbox SET attempt_count = 1, "
                    "last_error_code = 'acceptance_invalid', "
                    "last_error_digest = :digest, quarantined_at = :terminal_at "
                    "WHERE id = :id"
                ),
                {"id": event_id, "digest": terminal_digest, "terminal_at": terminal_at},
            )
    assert getattr(rejected.value.orig, "sqlstate", None) == "42501"


@pytest.mark.parametrize(
    ("retained_column", "retained_value"),
    (
        ("available_at", datetime(2030, 1, 1, tzinfo=timezone.utc)),
        ("claimed_at", datetime(2030, 1, 1, tzinfo=timezone.utc)),
        ("claim_token", uuid4()),
    ),
)
def test_real_postgresql_quarantine_rejects_retained_dispatch_state(
    postgresql_engine: Engine,
    retained_column: str,
    retained_value: object,
) -> None:
    event_id = uuid4()
    terminal_at = datetime.now(timezone.utc)
    terminal_digest = sha256(f"terminal-{retained_column}".encode()).hexdigest()
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox ("
                "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, available_at"
                ") VALUES ("
                ":id, NULL, 'acceptance', :aggregate_key, 'acceptance.quarantine_state', "
                "CAST('{}' AS jsonb), :idempotency_key, :request_hash, 0, NULL)"
            ),
            {
                "id": event_id,
                "aggregate_key": str(event_id),
                "idempotency_key": f"postgres-quarantine-state-{event_id}",
                "request_hash": sha256(event_id.bytes).hexdigest(),
            },
        )

    statement = sa.text(
        "UPDATE saas_control_plane_outbox SET attempt_count = 1, "
        "last_error_code = 'acceptance_invalid', last_error_digest = :digest, "
        f"quarantined_at = :terminal_at, {retained_column} = :retained_value "
        "WHERE id = :id"
    )
    with pytest.raises(DBAPIError, match="ck_outbox_quarantine_dispatch_clear") as rejected:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
            connection.execute(
                statement,
                {
                    "id": event_id,
                    "digest": terminal_digest,
                    "terminal_at": terminal_at,
                    "retained_value": retained_value,
                },
            )
    assert getattr(rejected.value.orig, "sqlstate", None) == "23514"


def test_real_postgresql_vertical_chain_obeys_onboarding_rls(
    isolated_onboarding_engine: Engine,
) -> None:
    postgresql_engine = isolated_onboarding_engine
    suffix = uuid4().hex[:12]
    # Keep synthetic stage timestamps behind PostgreSQL's wall clock.  This
    # preserves the causal activated_at <= Run.created_at <= completed_at
    # ordering while still exercising deterministic stage transitions.
    now = datetime.now(timezone.utc) - timedelta(minutes=3, seconds=10)
    policy = _policy()
    envelopes = VerificationEnvelopeKeyring(
        active_key_id="p0-vertical-postgresql-v1",
        keys={"p0-vertical-postgresql-v1": b"v" * 32},
    )
    registration_sessions = _role_sessions(postgresql_engine, "saas_registration")
    onboarding_sessions = _role_sessions(postgresql_engine, "saas_onboarding")
    registrations = SelfServiceOnboardingService(
        registration_sessions,
        policy=policy,
        envelope_keyring=envelopes,
        rate_limiter=_AllowAllRateLimiter(),
    )
    coordinator = TenantOnboardingCoordinator(onboarding_sessions, policy=policy)
    accepted = registrations.request_registration(
        email=f"vertical-{suffix}@example.test",
        display_name="Vertical Owner",
        tenant_name=f"Vertical Tenant {suffix}",
        tenant_slug=f"vertical-{suffix}",
        default_space_name="Default Space",
        default_space_slug="default",
        plan_key="starter",
        home_region="cn-east-1",
        idempotency_key=f"vertical-registration-{suffix}",
        now=now,
    )
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
        idempotency_key=f"vertical-verify-{suffix}",
        now=now + timedelta(minutes=1),
    )
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

    placement_id = uuid4()
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements ("
                "id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, "
                "capacity_class, status) VALUES ("
                ":id, 'omnigent', 'cn-east-1', 'cn-east-1a', 'runtime-db-test', "
                "'runtime-objects-test', 'runtime-kms-test', :schema_revision, "
                "'starter', 'active')"
            ),
            {"id": placement_id, "schema_revision": "e5d9bc8ac650"},
        )

    scope = OnboardingScope(
        onboarding_id=started.onboarding_id,
        registration_id=accepted.registration_id,
        actor_id=requested.user_id,
        tenant_id=requested.tenant_id,
    )
    observation_sessions = _role_sessions(postgresql_engine, "saas_executor")
    workflow = TenantOnboardingWorkflow(
        onboarding_sessions,
        runtime=_PostgresqlRuntime(placement_id),
        execution_session_factory=observation_sessions,
    )
    stage_now = now + timedelta(minutes=3)
    assert workflow.advance(scope, now=stage_now).status == "billing_ready"
    assert workflow.advance(scope, now=stage_now + timedelta(seconds=1)).status == "runtime_ready"
    assert workflow.advance(scope, now=stage_now + timedelta(seconds=2)).status == "project_ready"
    activated = workflow.advance(scope, now=stage_now + timedelta(seconds=3))
    assert activated.status == "active"

    request = RequestContext(
        actor_id=requested.user_id,
        tenant_id=requested.tenant_id,
        space_id=requested.space_id,
        project_id=requested.default_project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id=f"onboarding-postgresql-first-run-{suffix}",
    )
    execution = ExecutionControlPlane(_role_sessions(postgresql_engine, "saas_app"))
    task_id = execution.create_task(
        request,
        project_id=requested.default_project_id,
        title="First PostgreSQL onboarding Run",
    )
    observed = OnboardingFirstRunAdmissionAdapter(
        execution,
        CommittedRunAdmissionObserver(workflow),
    ).admit_first_run(
        scope,
        request,
        project_id=requested.default_project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"prompt": "Verify the PostgreSQL onboarding chain"},
        quota_resource="interactive_runs",
        quota_units=1,
        idempotency_key=f"postgresql-first-run-{suffix}",
        revisions=ExecutionRevisionSet(
            product_revision="wave1-product",
            upstream_revision="14df304a8e958da36b8a606a2c825e3a6642247e",
            schema_revision="e5d9bc8ac650",
            adapter_contract_version="0.2.0",
        ),
    )
    assert observed.admission.status == "queued"
    assert observed.onboarding.status == "completed"
    assert observed.onboarding.first_run_id == observed.admission.run_id

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        state = connection.execute(
            sa.text(
                "SELECT saga.status, tenant.status, tenant.lifecycle_version, space.status, "
                "project.status, subscription.status, entitlement.status, partition.status, "
                "alias.status, binding.status, quota.limit_units, saga.runtime_placement_id "
                "FROM saas_tenant_onboardings saga "
                "JOIN saas_tenants tenant ON tenant.id = saga.tenant_id "
                "JOIN saas_spaces space ON space.id = saga.space_id "
                "JOIN saas_projects project ON project.id = saga.default_project_id "
                "JOIN saas_billing_subscriptions subscription "
                "ON subscription.id = saga.subscription_id "
                "JOIN saas_billing_entitlements entitlement "
                "ON entitlement.id = saga.entitlement_id "
                "JOIN saas_runtime_partitions partition "
                "ON partition.id = saga.runtime_partition_id "
                "JOIN saas_runtime_identity_aliases alias "
                "ON alias.runtime_partition_id = saga.runtime_partition_id "
                "AND alias.user_id = saga.user_id "
                "JOIN saas_runtime_resource_bindings binding "
                "ON binding.id = saga.runtime_binding_id "
                "JOIN saas_admission_quotas quota "
                "ON quota.tenant_id = saga.tenant_id "
                "AND quota.space_id = saga.space_id "
                "AND quota.project_id = saga.default_project_id "
                "WHERE saga.id = :onboarding_id"
            ),
            {"onboarding_id": started.onboarding_id},
        ).one()
    assert state == (
        "completed",
        "trial",
        2,
        "active",
        "active",
        "trialing",
        "active",
        "active",
        "active",
        "active",
        100,
        placement_id,
    )


def test_real_postgresql_runtime_failure_compensates_exact_scope(
    isolated_onboarding_engine: Engine,
) -> None:
    postgresql_engine = isolated_onboarding_engine
    suffix = uuid4().hex[:12]
    now = datetime.now(timezone.utc)
    scope, onboarding_sessions = _create_started_scope(
        postgresql_engine,
        suffix=suffix,
        now=now,
    )
    placement_id = uuid4()
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements ("
                "id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, "
                "capacity_class, status) VALUES ("
                ":id, 'omnigent', 'cn-east-1', 'cn-east-1a', 'runtime-db-failure', "
                "'runtime-objects-failure', 'runtime-kms-failure', :schema_revision, "
                "'starter', 'active')"
            ),
            {"id": placement_id, "schema_revision": "e5d9bc8ac650"},
        )

    runtime = _PostgresqlRuntime(placement_id, allocation_failures_remaining=1)
    workflow = TenantOnboardingWorkflow(
        onboarding_sessions,
        runtime=runtime,
        execution_session_factory=_role_sessions(postgresql_engine, "saas_executor"),
        max_attempts=1,
    )
    stage_now = now + timedelta(minutes=3)
    assert workflow.advance(scope, now=stage_now).status == "billing_ready"
    failed = workflow.advance(scope, now=stage_now + timedelta(seconds=1))
    assert failed.status == "compensating"
    assert workflow.advance(scope, now=stage_now + timedelta(seconds=2)).status == "compensating"
    compensated = workflow.advance(scope, now=stage_now + timedelta(seconds=3))
    assert compensated.status == "compensated"
    assert runtime.partition_compensations == 1

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        state = connection.execute(
            sa.text(
                "SELECT saga.status, saga.failure_stage, saga.compensation_cursor, "
                "tenant.status, tenant.lifecycle_version, space.status, "
                "subscription.status, entitlement.status "
                "FROM saas_tenant_onboardings saga "
                "JOIN saas_tenants tenant ON tenant.id = saga.tenant_id "
                "JOIN saas_spaces space ON space.id = saga.space_id "
                "JOIN saas_billing_subscriptions subscription "
                "ON subscription.id = saga.subscription_id "
                "JOIN saas_billing_entitlements entitlement "
                "ON entitlement.id = saga.entitlement_id "
                "WHERE saga.id = :onboarding_id"
            ),
            {"onboarding_id": scope.onboarding_id},
        ).one()
    assert state == (
        "compensated",
        "billing_ready",
        None,
        "suspended",
        2,
        "suspended",
        "canceled",
        "suspended",
    )


def test_real_postgresql_runtime_partition_is_bound_to_frozen_placement(
    isolated_onboarding_engine: Engine,
) -> None:
    postgresql_engine = isolated_onboarding_engine
    suffix = uuid4().hex[:12]
    now = datetime.now(timezone.utc)
    scope, onboarding_sessions = _create_started_scope(
        postgresql_engine,
        suffix=f"partition-placement-{suffix}",
        now=now,
    )
    placement_id, wrong_placement_id = uuid4(), uuid4()
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements ("
                "id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, "
                "capacity_class, status) VALUES "
                "(:placement_id, 'omnigent', 'cn-east-1', 'cn-east-1a', "
                "'runtime-db-exact', 'runtime-objects-exact', 'runtime-kms-exact', "
                ":schema_revision, 'starter', 'active'), "
                "(:wrong_placement_id, 'omnigent', 'other-region', 'other-region-a', "
                "'runtime-db-wrong', 'runtime-objects-wrong', 'runtime-kms-wrong', "
                ":schema_revision, 'starter', 'active')"
            ),
            {
                "placement_id": placement_id,
                "wrong_placement_id": wrong_placement_id,
                "schema_revision": "e5d9bc8ac650",
            },
        )

    runtime = _PostgresqlRuntime(placement_id, allocation_failures_remaining=1)
    workflow = TenantOnboardingWorkflow(
        onboarding_sessions,
        runtime=runtime,
        execution_session_factory=_role_sessions(postgresql_engine, "saas_executor"),
    )
    stage_now = now + timedelta(minutes=3)
    assert workflow.advance(scope, now=stage_now).status == "billing_ready"
    frozen_retry = workflow.advance(scope, now=stage_now + timedelta(seconds=1))
    assert frozen_retry.status == "billing_ready"

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        saga = connection.execute(
            sa.text(
                "SELECT runtime_partition_id, runtime_placement_id, space_id, user_id, "
                "runtime_target_snapshot ->> 'placement_id' AS snapshot_placement_id "
                "FROM saas_tenant_onboardings WHERE id = :onboarding_id"
            ),
            {"onboarding_id": scope.onboarding_id},
        ).one()
    frozen_placement_id = saga.runtime_placement_id
    assert saga.snapshot_placement_id == str(frozen_placement_id)
    runtime.placement_id = frozen_placement_id
    runtime.allocation_failures_remaining = 0
    wrong_partition = {
        "runtime_partition_id": saga.runtime_partition_id,
        "tenant_id": scope.tenant_id,
        "space_id": saga.space_id,
        "wrong_placement_id": wrong_placement_id,
        "physical_partition_key": str(int(saga.runtime_partition_id.hex[:12], 16) or 1),
        "source_revision": "14df304a8e958da36b8a606a2c825e3a6642247e",
    }
    insert_wrong_partition = sa.text(
        "INSERT INTO saas_runtime_partitions ("
        "id, tenant_id, space_id, placement_id, runtime_type, runtime_version, "
        "physical_partition_key, placement_generation, source_revision, "
        "adapter_contract_version, status) VALUES ("
        ":runtime_partition_id, :tenant_id, :space_id, :wrong_placement_id, "
        "'omnigent', '0.11.0.dev0', :physical_partition_key, 1, :source_revision, "
        "'0.2.0', 'active')"
    )

    with pytest.raises(DBAPIError) as wrong_placement_insert:
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding")
            _set_guc(connection, "app.registration_id", scope.registration_id)
            _set_guc(connection, "app.onboarding_id", scope.onboarding_id)
            _set_guc(connection, "app.actor_id", scope.actor_id)
            _set_guc(connection, "app.tenant_id", scope.tenant_id)
            connection.execute(insert_wrong_partition, wrong_partition)
    _assert_rls_denied(wrong_placement_insert.value)

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(insert_wrong_partition, wrong_partition)

    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding")
        _set_guc(connection, "app.registration_id", scope.registration_id)
        _set_guc(connection, "app.onboarding_id", scope.onboarding_id)
        _set_guc(connection, "app.actor_id", scope.actor_id)
        _set_guc(connection, "app.tenant_id", scope.tenant_id)
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM saas_runtime_partitions WHERE id = :runtime_partition_id"
                ),
                wrong_partition,
            ).scalar_one()
            == 0
        )

    conflicted = workflow.advance(scope, now=stage_now + timedelta(seconds=7))
    assert conflicted.status == "billing_ready"
    with postgresql_engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        state = connection.execute(
            sa.text(
                "SELECT status, runtime_ready_at, last_error_code, runtime_placement_id "
                "FROM saas_tenant_onboardings WHERE id = :onboarding_id"
            ),
            {"onboarding_id": scope.onboarding_id},
        ).one()
    assert state == (
        "billing_ready",
        None,
        "onboarding_internal_error",
        frozen_placement_id,
    )


def test_production_composition_requires_four_exact_login_authorities_and_sealed_runtime(
    postgresql_engine: Engine,
) -> None:
    suffix = uuid4().hex[:12]
    password = f"Onboarding-{uuid4().hex}"
    role_by_authority: dict[OnboardingDatabaseAuthority, str] = {
        "registration": "saas_registration",
        "onboarding": "saas_onboarding",
        "execution": "saas_executor",
        "status": "saas_onboarding_status",
    }
    login_by_authority = {
        authority: f"onboarding_{authority}_{suffix}" for authority in role_by_authority
    }
    created_logins: list[str] = []
    login_engines: dict[str, Engine] = {}

    try:
        with postgresql_engine.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote
            for authority, base_role in role_by_authority.items():
                login = login_by_authority[authority]
                quoted_login = quote(login)
                connection.exec_driver_sql(
                    f"CREATE ROLE {quoted_login} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                    f"NOCREATEROLE NOREPLICATION NOBYPASSRLS "
                    f"PASSWORD '{password}'"
                )
                created_logins.append(login)
                connection.exec_driver_sql(f"GRANT {base_role} TO {quoted_login}")
                connection.exec_driver_sql(f"ALTER ROLE {quoted_login} SET search_path = public")

        for authority, login in login_by_authority.items():
            engine = sa.create_engine(
                postgresql_engine.url.set(username=login, password=password),
                pool_pre_ping=True,
            )
            login_engines[authority] = engine
            verify_onboarding_database_authority(engine, authority=authority)

        # A grant option on an already-allowed column does not change the
        # effective projection returned by has_column_privilege().  The verifier
        # must inspect the underlying ACL and reject the delegation authority.
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT SELECT (status) ON saas_tenant_onboardings "
                "TO saas_onboarding_status WITH GRANT OPTION"
            )
        try:
            login_engines["status"].dispose()
            with pytest.raises(RuntimeError, match=r"grant options.*default ACLs"):
                verify_onboarding_database_authority(login_engines["status"], authority="status")
        finally:
            with postgresql_engine.begin() as connection:
                connection.exec_driver_sql(
                    "REVOKE GRANT OPTION FOR SELECT (status) "
                    "ON saas_tenant_onboardings FROM saas_onboarding_status CASCADE"
                )
        verify_onboarding_database_authority(login_engines["status"], authority="status")

        # Default ACLs can silently widen future tables even when every current
        # object still matches the allowlist.
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES "
                "TO saas_onboarding_status"
            )
        try:
            login_engines["status"].dispose()
            with pytest.raises(RuntimeError, match=r"grant options.*default ACLs"):
                verify_onboarding_database_authority(login_engines["status"], authority="status")
        finally:
            with postgresql_engine.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES "
                    "FROM saas_onboarding_status"
                )
        verify_onboarding_database_authority(login_engines["status"], authority="status")

        with postgresql_engine.connect() as connection:
            server_version_num = int(
                connection.execute(
                    sa.text("SELECT current_setting('server_version_num')::integer")
                ).scalar_one()
            )
        if server_version_num >= 170000:
            with postgresql_engine.begin() as connection:
                connection.exec_driver_sql(
                    "GRANT MAINTAIN ON saas_tenant_onboardings TO saas_onboarding_status"
                )
            try:
                login_engines["status"].dispose()
                with pytest.raises(RuntimeError, match="exact read-only projection"):
                    verify_onboarding_database_authority(
                        login_engines["status"], authority="status"
                    )
            finally:
                with postgresql_engine.begin() as connection:
                    connection.exec_driver_sql(
                        "REVOKE MAINTAIN ON saas_tenant_onboardings FROM saas_onboarding_status"
                    )
            verify_onboarding_database_authority(login_engines["status"], authority="status")

        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT SELECT (last_error_detail) ON saas_tenant_onboardings "
                "TO saas_onboarding_status"
            )
        login_engines["status"].dispose()
        with pytest.raises(RuntimeError, match="exact read-only projection"):
            verify_onboarding_database_authority(login_engines["status"], authority="status")
        with postgresql_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE SELECT (last_error_detail) ON saas_tenant_onboardings "
                "FROM saas_onboarding_status"
            )

        with pytest.raises(RuntimeError, match="construction-sealed"):
            TenantOnboardingDependencies(
                registration_sessions=sessionmaker(
                    login_engines["registration"], expire_on_commit=False
                ),
                onboarding_sessions=sessionmaker(
                    login_engines["onboarding"], expire_on_commit=False
                ),
                execution_sessions=sessionmaker(
                    login_engines["execution"], expire_on_commit=False
                ),
                policy=_policy(),
                envelopes=VerificationEnvelopeKeyring(
                    active_key_id=f"authority-{suffix}",
                    keys={f"authority-{suffix}": b"a" * 32},
                ),
                rate_limiter=_AllowAllRateLimiter(),
                email_sender=_DiscardingEmailSender(),
                runtime=object.__new__(ProductionRuntimePartitionAdapter),
            )

        registration_login = login_by_authority["registration"]
        with postgresql_engine.begin() as connection:
            quoted_login = connection.dialect.identifier_preparer.quote(registration_login)
            connection.exec_driver_sql(f"GRANT saas_platform TO {quoted_login}")
        login_engines["registration"].dispose()
        with pytest.raises(RuntimeError, match="inherit only saas_registration"):
            verify_onboarding_database_authority(
                login_engines["registration"], authority="registration"
            )
        with postgresql_engine.begin() as connection:
            quoted_login = connection.dialect.identifier_preparer.quote(registration_login)
            connection.exec_driver_sql(f"REVOKE saas_platform FROM {quoted_login}")
    finally:
        for engine in login_engines.values():
            engine.dispose()
        if created_logins:
            with postgresql_engine.begin() as connection:
                quote = connection.dialect.identifier_preparer.quote
                for login in reversed(created_logins):
                    connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quote(login)}")
