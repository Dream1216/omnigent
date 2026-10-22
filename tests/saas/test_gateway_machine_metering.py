from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from saas.control_plane.billing import BillingControlPlane
from saas.control_plane.billing_metering import BillingMeteringAuthority, BillingMeteringError
from saas.control_plane.billing_models import (
    BillingMeteringReceiptRecord,
    BillingSubscriptionRecord,
    UsageEventRecord,
)
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_gateway_metering import read_gateway_metering_fact
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import ModelProviderMonthlyBudgetRecord
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from saas.production.runner_control import ProductionRunnerMachineAuthority
from tests.saas.test_billing_metering_transport import _certificate_fixture
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runtime import _running_lease, _runtime_authority
from tests.saas.test_model_run_credentials import _service
from tests.saas.test_model_run_evidence import _enable_budget, _reserve


def _customer_prices(factory, *, actor, tenant, rate=25):
    billing = BillingControlPlane(factory)
    now = datetime.now(timezone.utc)
    with factory() as db:
        version = db.scalar(
            sa.select(BillingSubscriptionRecord.version).where(
                BillingSubscriptionRecord.tenant_id == tenant
            )
        )
    key = f"gateway-plan-{rate}"
    billing.configure_subscription(
        actor_id=actor,
        tenant_id=tenant,
        plan_key=key,
        status="active",
        current_period_start=now - timedelta(hours=1),
        current_period_end=now + timedelta(days=30),
        expected_version=version,
        idempotency_key=key + "-subscription",
    )
    return billing.create_pricing_snapshot(
        actor_id=actor,
        tenant_id=tenant,
        plan_key=key,
        currency="USD",
        rates={
            meter: {"unit": "tokens", "unit_size": "1000", "minor_per_unit": amount}
            for meter, amount in (("llm.input_tokens", rate), ("llm.output_tokens", rate * 3))
        },
        effective_from=now - timedelta(hours=1),
        effective_until=now + timedelta(days=30),
        idempotency_key=key + "-prices",
    ).id


def _register_metering_certificate(factory, runner_id, generation, tmp_path):
    certificates = _certificate_fixture(tmp_path, (runner_id,))
    der = x509.load_pem_x509_certificate(
        certificates["runner-0"].certificate.read_bytes()
    ).public_bytes(serialization.Encoding.DER)
    registration = RunnerCertificateAuthority(factory, accepted_trust_bundle_versions=("test-v1",))
    activated = registration.activate_certificate(
        runner_id=runner_id,
        runner_connection_generation=generation,
        purpose="billing_metering",
        certificate_der=der,
        trust_bundle_version="test-v1",
    )
    return certificates, activated.fingerprint_sha256


async def _prepared(f, tmp_path, *, settle=True, terminal=True, usage=None):
    price = _customer_prices(f.factory, actor=f.runtime.actor_id, tenant=f.runtime.tenant_id)
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority)
    issued = service.issue(await authority.authorize(lease), lease)
    grant = service.authorize(service.authenticate(issued.value))
    assert grant.customer_pricing_snapshot_id == price
    certificates, fingerprint = _register_metering_certificate(
        f.factory, connection.runner_id, connection.connection_generation, tmp_path
    )
    _enable_budget(f.factory)
    budgets = ModelProviderBudgetAdmissionService(f.factory)
    hold = _reserve(budgets, grant)
    budgets.begin_attempt(reservation_id=hold.id)
    if settle:
        usage = usage or ModelTokenUsage(10, 0, 10, 3, 13)
        actual = grant.gateway_request(output_token_limit=32).model_price.cost(
            usage, at=datetime.now(timezone.utc)
        )
        budgets.resolve_attempt(
            reservation_id=hold.id,
            actual_microusd=actual,
            actual_tokens=usage.total_tokens,
            evidence_sha256=None,
            gateway_usage=usage,
        )
    else:
        budgets.mark_uncertain(reservation_id=hold.id)
    if terminal:
        machine = ProductionRunnerMachineAuthority(
            SchedulingControlPlane(f.factory), ExecutionControlPlane(f.factory)
        )
        channel = {
            "runner_id": connection.runner_id,
            "connection_generation": connection.connection_generation,
            "connection_token": connection.connection_token,
        }
        machine.transition_run(
            **channel,
            run_id=lease.run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            capability_token=lease.capability_token,
            target_status="succeeded",
        )
        machine.release_run(**channel, run_id=lease.run_id, fence_token=lease.fence_token)
    return lease, fingerprint, price, hold, certificates


def _request(factory, lease, fingerprint, hold, meter="llm.input_tokens"):
    with factory() as db:
        cap = db.get(CapabilityTokenRecord, lease.capability_id)
        fact = read_gateway_metering_fact(db, reservation_id=hold.id, capability=cap)
        return {
            **fact.submission(meter),
            "runner_id": cap.runner_id,
            "run_id": lease.run_id,
            "capability_token": lease.capability_token,
            "certificate_fingerprint_sha256": fingerprint,
        }


@pytest.mark.parametrize("interactive_http", [False, True], indirect=True)
@pytest.mark.asyncio
async def test_gateway_usage_enters_the_existing_machine_authority_once_after_run_release(
    interactive_http, tmp_path
):
    f = interactive_http
    lease, fingerprint, price, hold, _ = await _prepared(f, tmp_path)
    _customer_prices(f.factory, actor=f.runtime.actor_id, tenant=f.runtime.tenant_id, rate=2500)
    authority = BillingMeteringAuthority(f.factory)
    with f.factory() as db:
        before = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd))
        cap = db.get(CapabilityTokenRecord, lease.capability_id)
        assert cap.revoked_at is not None
        future = cap.expires_at.replace(tzinfo=timezone.utc) + timedelta(seconds=1)
        assert set(cap.allowed_actions) == {"run.execute", "runtime.interactive.execute"}
    for meter in ("llm.input_tokens", "llm.output_tokens"):
        request = _request(f.factory, lease, fingerprint, hold, meter)
        result = authority.record_usage(**request, now=future)
        assert result.pricing_snapshot_id == price and result.customer_charge_minor == 1
        assert authority.record_usage(**request, now=future).receipt_id == result.receipt_id
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(BillingMeteringReceiptRecord)) == 2
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == "billing.usage.recorded")
            )
            == 2
        )
        assert db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd)) == before


@pytest.mark.parametrize("interactive_http", [False, True], indirect=True)
@pytest.mark.asyncio
async def test_gateway_machine_usage_rejects_observer_and_caller_selected_values(
    interactive_http, tmp_path
):
    f = interactive_http
    lease, fingerprint, _, hold, _ = await _prepared(f, tmp_path, terminal=False)
    authority = BillingMeteringAuthority(f.factory)
    request = _request(f.factory, lease, fingerprint, hold)
    for mutation in (
        {"quantity": "11"},
        {"quantity": "10.0"},
        {"meter": "sandbox.seconds"},
        {"provider_request_id": "omnigent-observer-random"},
        {"idempotency_key": "another-charge"},
        {"attributes": {"model": "other"}},
        {"model_budget_reservation_id": None},
    ):
        with pytest.raises(BillingMeteringError):
            authority.record_usage(**{**request, **mutation})
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
    assert authority.record_usage(**request).quantity == Decimal(10)
    with f.factory() as db:
        subscription = db.scalar(
            sa.select(BillingSubscriptionRecord).where(
                BillingSubscriptionRecord.tenant_id == f.runtime.tenant_id,
            )
        )
        plan, version = subscription.plan_key, subscription.version
        start = subscription.current_period_start.replace(tzinfo=timezone.utc)
        end = subscription.current_period_end.replace(tzinfo=timezone.utc)
    BillingControlPlane(f.factory).configure_subscription(
        actor_id=f.runtime.actor_id,
        tenant_id=f.runtime.tenant_id,
        plan_key=plan,
        status="canceled",
        current_period_start=start,
        current_period_end=end,
        expected_version=version,
        idempotency_key="cancel-gateway-subscription",
    )
    with pytest.raises(BillingMeteringError) as denied:
        authority.record_usage(
            **_request(f.factory, lease, fingerprint, hold, "llm.output_tokens")
        )
    assert denied.value.code == "metering_subscription_unavailable"
    assert authority.record_usage(**request).replayed


@pytest.mark.asyncio
async def test_unknown_provider_outcome_cannot_become_estimated_customer_usage(
    interactive_http, tmp_path
):
    f = interactive_http
    lease, fingerprint, _, hold, _ = await _prepared(f, tmp_path, settle=False, terminal=False)
    authority = BillingMeteringAuthority(f.factory)
    with f.factory() as db:
        runner_id = db.get(CapabilityTokenRecord, lease.capability_id).runner_id
    with pytest.raises(BillingMeteringError):
        authority.record_usage(
            runner_id=runner_id,
            run_id=lease.run_id,
            capability_token=lease.capability_token,
            certificate_fingerprint_sha256=fingerprint,
            meter="llm.input_tokens",
            quantity=10,
            unit="tokens",
            provider="deepseek",
            provider_request_id=f"model-gateway:{hold.id}",
            idempotency_key=f"model-gateway:{hold.id}:input",
            occurred_at=datetime.now(timezone.utc),
            model_budget_reservation_id=hold.id,
        )


@pytest.mark.asyncio
async def test_explicit_zero_gateway_outcome_yields_no_customer_charge(interactive_http, tmp_path):
    f = interactive_http
    lease, _, _, hold, _ = await _prepared(
        f,
        tmp_path,
        usage=ModelTokenUsage(0, 0, 0, 0, 0),
    )
    with f.factory() as db:
        cap = db.get(CapabilityTokenRecord, lease.capability_id)
        fact = read_gateway_metering_fact(db, reservation_id=hold.id, capability=cap)
        assert fact.submissions() == ()
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
