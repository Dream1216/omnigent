from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane import (
    BillingControlPlane,
    BillingMeteringAuthority,
    BillingMeteringError,
    BillingMeteringReceiptRecord,
    CapabilityTokenRecord,
    ControlPlaneOutboxEvent,
    ExecutionControlPlane,
    ExecutionRevisionSet,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    RunnerCertificateRecord,
    RunnerRegistrationRecord,
    RunRecord,
    RuntimePlacementRecord,
    SaasBase,
    SchedulingControlPlane,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
    UsageEventRecord,
)


@dataclass(frozen=True, slots=True)
class _Fixture:
    factory: sessionmaker[Session]
    authority: BillingMeteringAuthority
    owner_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    run_id: UUID
    runner_id: UUID
    capability_token: str
    fingerprint: str
    now: datetime


@pytest.fixture
def metering() -> _Fixture:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @sa.event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection: object, _record: object) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[attr-defined]

    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    execution = ExecutionControlPlane(factory)
    scheduling = SchedulingControlPlane(factory)
    billing = BillingControlPlane(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    owner_id, tenant_id, space_id, project_id, placement_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    context = RequestContext(
        actor_id=owner_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="machine-metering",
    )
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(id=owner_id, status="active", security_version=1),
                RuntimePlacementRecord(
                    id=placement_id,
                    runtime_type="omnigent",
                    data_region="cn-east-1",
                    failure_domain="cn-east-1a",
                    database_cluster_ref="db-a",
                    object_store_ref="objects-a",
                    kms_key_ref="kms-a",
                    official_schema_revision="runtime-schema-v1",
                    capacity_class="shared-medium",
                    status="active",
                ),
                Tenant(
                    id=tenant_id,
                    slug=f"metering-{tenant_id.hex}",
                    name="Metering",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=owner_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                Space(
                    id=space_id,
                    tenant_id=tenant_id,
                    slug="engineering",
                    name="Engineering",
                    status="active",
                ),
            ]
        )
        db.flush()
        db.add(
            SpaceMembership(
                tenant_id=tenant_id,
                space_id=space_id,
                user_id=owner_id,
                role="owner",
                status="active",
                version=1,
            )
        )
        db.add(
            ProjectRecord(
                id=project_id,
                tenant_id=tenant_id,
                space_id=space_id,
                name="Metering project",
                visibility="restricted",
                created_by=owner_id,
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                subject_type="user",
                subject_id=owner_id,
                role="owner",
                status="active",
                created_by=owner_id,
                version=1,
            )
        )

    execution.configure_quota(
        context,
        project_id=project_id,
        resource="run_units",
        limit_units=10,
    )
    task_id = execution.create_task(context, project_id=project_id, title="Metered Run")
    run_id = execution.admit_run(
        context,
        project_id=project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"content": "must-never-be-visible-to-metering-role"},
        quota_resource="run_units",
        quota_units=1,
        idempotency_key="metered-run",
        revisions=ExecutionRevisionSet(
            product_revision="product",
            upstream_revision="upstream",
            schema_revision="p6a000000009",
            adapter_contract_version="0.2.0",
        ),
    ).run_id
    pool_id = scheduling.create_pool(
        placement_id=placement_id,
        name="metering-pool",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    scheduling.configure_tenant_share(
        tenant_id=tenant_id,
        pool_id=pool_id,
        weight=1,
        max_concurrent=1,
        burst_limit=1,
    )
    scheduling.prepare_dispatch(
        run_id=run_id,
        pool_id=pool_id,
        required_capabilities=["shell"],
        eligible_at=now - timedelta(seconds=1),
        maximum_wait=timedelta(hours=1),
    )
    runner = scheduling.register_runner(
        pool_id=pool_id,
        instance_key="runner-metering",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["shell"],
        max_concurrency=1,
        now=now,
    )
    lease = scheduling.claim_fair_run(
        runner_id=runner.runner_id,
        connection_generation=runner.connection_generation,
        connection_token=runner.connection_token,
        lease_duration=timedelta(minutes=10),
        capability_actions=["billing.usage.record"],
        capability_resource_scope={
            "billing_meters": "llm.input_tokens,llm.output_tokens",
        },
        now=now + timedelta(seconds=1),
    )
    assert lease is not None
    fingerprint = "a" * 64
    with factory.begin() as db:
        db.add(
            RunnerCertificateRecord(
                runner_id=runner.runner_id,
                runner_connection_generation=runner.connection_generation,
                purpose="billing_metering",
                fingerprint_sha256=fingerprint,
                spki_sha256="b" * 64,
                serial_hex="1234",
                spiffe_id=f"spiffe://omnigent/runner/{runner.runner_id}",
                trust_bundle_version="test-v1",
                rotation_generation=1,
                certificate_not_before=now - timedelta(minutes=1),
                certificate_not_after=now + timedelta(hours=1),
                status="active",
                activated_at=now,
            )
        )
    billing.configure_subscription(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v1",
        status="active",
        current_period_start=now - timedelta(hours=1),
        current_period_end=now + timedelta(days=30),
        expected_version=None,
        idempotency_key="metering-subscription",
    )
    billing.create_pricing_snapshot(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v1",
        currency="USD",
        rates={
            "llm.input_tokens": {
                "unit": "tokens",
                "unit_size": "1000",
                "minor_per_unit": 25,
            },
            "llm.output_tokens": {
                "unit": "tokens",
                "unit_size": "1000",
                "minor_per_unit": 50,
            },
        },
        effective_from=now - timedelta(hours=1),
        effective_until=now + timedelta(days=30),
        idempotency_key="metering-pricing",
    )
    yield _Fixture(
        factory=factory,
        authority=BillingMeteringAuthority(factory),
        owner_id=owner_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        run_id=run_id,
        runner_id=runner.runner_id,
        capability_token=lease.capability_token,
        fingerprint=fingerprint,
        now=now + timedelta(seconds=2),
    )
    engine.dispose()


def _record(fixture: _Fixture, **overrides: object):
    values: dict[str, object] = {
        "runner_id": fixture.runner_id,
        "certificate_fingerprint_sha256": fixture.fingerprint,
        "capability_token": fixture.capability_token,
        "run_id": fixture.run_id,
        "meter": "llm.input_tokens",
        "quantity": "1500",
        "unit": "tokens",
        "provider": "openai",
        "provider_request_id": "provider-request-1",
        "idempotency_key": "metering-event-1",
        "occurred_at": fixture.now,
        "attributes": {"model": "gpt-5"},
        "now": fixture.now,
    }
    values.update(overrides)
    return fixture.authority.record_usage(**values)  # type: ignore[arg-type]


def test_machine_metering_derives_scope_prices_and_persists_identity_atomically(
    metering: _Fixture,
) -> None:
    created = _record(metering)
    assert created.tenant_id == metering.tenant_id
    assert created.space_id == metering.space_id
    assert created.project_id == metering.project_id
    assert created.run_id == metering.run_id
    assert created.runner_id == metering.runner_id
    assert created.customer_charge_minor == 38
    assert created.replayed is False

    replayed = _record(metering)
    assert replayed.receipt_id == created.receipt_id
    assert replayed.usage_event_id == created.usage_event_id
    assert replayed.replayed is True

    with metering.factory() as db:
        receipt = db.get(BillingMeteringReceiptRecord, created.receipt_id)
        usage = db.get(UsageEventRecord, created.usage_event_id)
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(created.usage_event_id)
            )
        )
        assert receipt is not None
        assert usage is not None
        assert event is not None
        assert receipt.capability_id is not None
        assert receipt.fence_token > 0
        assert usage.user_id == metering.owner_id
        assert usage.session_id is None
        assert event.payload["metering_receipt_id"] == str(receipt.id)
        assert metering.capability_token not in str(event.payload)
        assert "must-never-be-visible" not in str(event.payload)


def test_machine_metering_fails_closed_for_scope_replay_and_stale_execution(
    metering: _Fixture,
) -> None:
    with pytest.raises(BillingMeteringError) as meter_denied:
        _record(metering, meter="storage.bytes")
    assert meter_denied.value.code == "metering_capability_scope_denied"

    _record(metering)
    with pytest.raises(BillingMeteringError) as conflict:
        _record(metering, quantity="1501")
    assert conflict.value.code == "metering_idempotency_conflict"

    with metering.factory.begin() as db:
        run = db.get(RunRecord, metering.run_id)
        assert run is not None
        run.fence_token += 1
    with pytest.raises(BillingMeteringError) as stale:
        _record(
            metering,
            provider_request_id="provider-request-2",
            idempotency_key="metering-event-2",
        )
    assert stale.value.code == "metering_fence_stale"


def test_machine_metering_rejects_revoked_or_expired_capabilities(metering: _Fixture) -> None:
    digest = sha256(metering.capability_token.encode()).hexdigest()
    with metering.factory.begin() as db:
        capability = db.scalar(
            sa.select(CapabilityTokenRecord).where(CapabilityTokenRecord.token_hash == digest)
        )
        assert capability is not None
        capability.revoked_at = metering.now - timedelta(milliseconds=1)
        capability.revocation_reason = "test revocation"
    with pytest.raises(BillingMeteringError) as revoked:
        _record(metering)
    assert revoked.value.code == "metering_capability_expired"

    with metering.factory.begin() as db:
        capability = db.scalar(
            sa.select(CapabilityTokenRecord).where(CapabilityTokenRecord.token_hash == digest)
        )
        assert capability is not None
        capability.revoked_at = None
        capability.revocation_reason = None
        capability.expires_at = metering.now - timedelta(milliseconds=1)
    with pytest.raises(BillingMeteringError) as expired:
        _record(metering)
    assert expired.value.code == "metering_capability_expired"


def test_machine_metering_rejects_wrong_action_revoked_certificate_and_reconnect(
    metering: _Fixture,
) -> None:
    digest = sha256(metering.capability_token.encode()).hexdigest()
    with metering.factory.begin() as db:
        capability = db.scalar(
            sa.select(CapabilityTokenRecord).where(CapabilityTokenRecord.token_hash == digest)
        )
        assert capability is not None
        capability.allowed_actions = ["worktree.materialize"]
    with pytest.raises(BillingMeteringError) as action:
        _record(metering)
    assert action.value.code == "metering_capability_action_denied"

    with metering.factory.begin() as db:
        capability = db.scalar(
            sa.select(CapabilityTokenRecord).where(CapabilityTokenRecord.token_hash == digest)
        )
        certificate = db.scalar(
            sa.select(RunnerCertificateRecord).where(
                RunnerCertificateRecord.fingerprint_sha256 == metering.fingerprint
            )
        )
        assert capability is not None
        assert certificate is not None
        capability.allowed_actions = ["billing.usage.record"]
        certificate.status = "revoked"
        certificate.revoked_at = metering.now
        certificate.revocation_reason = "test revocation"
    with pytest.raises(BillingMeteringError) as certificate_denied:
        _record(metering)
    assert certificate_denied.value.code == "metering_certificate_denied"

    with metering.factory.begin() as db:
        certificate = db.scalar(
            sa.select(RunnerCertificateRecord).where(
                RunnerCertificateRecord.fingerprint_sha256 == metering.fingerprint
            )
        )
        runner = db.get(RunnerRegistrationRecord, metering.runner_id)
        assert certificate is not None
        assert runner is not None
        certificate.status = "active"
        certificate.revoked_at = None
        certificate.revocation_reason = None
        runner.connection_generation += 1
    with pytest.raises(BillingMeteringError) as reconnect:
        _record(metering)
    assert reconnect.value.code == "metering_certificate_denied"


def test_machine_metering_rejects_unbound_runner_and_sensitive_attributes(
    metering: _Fixture,
) -> None:
    with pytest.raises(BillingMeteringError) as runner:
        _record(metering, runner_id=uuid4())
    assert runner.value.code == "metering_certificate_denied"

    with pytest.raises(BillingMeteringError) as attributes:
        _record(metering, attributes={"prompt_digest": "still forbidden"})
    assert attributes.value.code == "metering_attributes_sensitive"
