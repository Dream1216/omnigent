from __future__ import annotations

import os
from collections.abc import Iterator
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
from saas.control_plane.onboarding_workflow import (
    OnboardingScope,
    RuntimePartitionAllocation,
    RuntimePartitionTarget,
    RuntimeProjectAllocation,
    RuntimeProjectTarget,
    TenantOnboardingWorkflow,
)
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
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


def test_real_postgresql_vertical_chain_obeys_onboarding_rls(
    postgresql_engine: Engine,
) -> None:
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
    postgresql_engine: Engine,
) -> None:
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
    postgresql_engine: Engine,
) -> None:
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


def test_production_composition_requires_three_exact_login_authorities(
    postgresql_engine: Engine,
) -> None:
    suffix = uuid4().hex[:12]
    password = f"Onboarding-{uuid4().hex}"
    role_by_authority: dict[OnboardingDatabaseAuthority, str] = {
        "registration": "saas_registration",
        "onboarding": "saas_onboarding",
        "execution": "saas_executor",
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
                    f"CREATE ROLE {quoted_login} LOGIN INHERIT NOSUPERUSER NOBYPASSRLS "
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

        TenantOnboardingDependencies(
            registration_sessions=sessionmaker(
                login_engines["registration"], expire_on_commit=False
            ),
            onboarding_sessions=sessionmaker(login_engines["onboarding"], expire_on_commit=False),
            execution_sessions=sessionmaker(login_engines["execution"], expire_on_commit=False),
            policy=_policy(),
            envelopes=VerificationEnvelopeKeyring(
                active_key_id=f"authority-{suffix}",
                keys={f"authority-{suffix}": b"a" * 32},
            ),
            rate_limiter=_AllowAllRateLimiter(),
            email_sender=_DiscardingEmailSender(),
            runtime=_PostgresqlRuntime(uuid4()),
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
