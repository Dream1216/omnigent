from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.billing import BillingControlPlane
from saas.control_plane.billing_metering import BillingMeteringAuthority, BillingMeteringError
from saas.control_plane.billing_models import (
    BillingSubscriptionRecord,
    PricingSnapshotRecord,
    UsageEventRecord,
)
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord
from tests.saas.test_billing_metering import _record
from tests.saas.test_billing_metering import metering as metering
from tests.saas.test_execution_control_plane import _revisions, _task_admission
from tests.saas.test_execution_control_plane import (
    execution_control_plane as execution_control_plane,
)


def _plan(factory, scope, *, key="team-v1", version=None, priced=True, rate=25):
    billing = BillingControlPlane(factory)
    now = datetime.now(timezone.utc)
    billing.configure_subscription(
        actor_id=scope.owner_id,
        tenant_id=scope.tenant_id,
        plan_key=key,
        status="active",
        current_period_start=now - timedelta(hours=1),
        current_period_end=now + timedelta(days=30),
        expected_version=version,
        idempotency_key="subscription-" + uuid4().hex,
    )
    if not priced:
        return None
    return billing.create_pricing_snapshot(
        actor_id=scope.owner_id,
        tenant_id=scope.tenant_id,
        plan_key=key,
        currency="USD",
        rates={
            "llm.input_tokens": {"unit": "tokens", "unit_size": "1000", "minor_per_unit": rate}
        },
        effective_from=now - timedelta(hours=1),
        effective_until=now + timedelta(days=30),
        idempotency_key="pricing-" + uuid4().hex,
    ).id


def _admit(service, scope, context, *, session_id=None):
    service.configure_quota(context, project_id=scope.project_id, resource="run", limit_units=100)
    task = service.create_task(context, project_id=scope.project_id, title="Priced execution")
    if session_id is not None:
        service.attach_task(
            context, project_id=scope.project_id, session_id=session_id, task_id=task
        )
    return service.admit_run(
        context,
        project_id=scope.project_id,
        task_id=task,
        session_id=session_id,
        input_payload={"execution": "fixture"},
        quota_resource="run",
        quota_units=1,
        idempotency_key="run-" + uuid4().hex,
        revisions=_revisions(),
    ).run_id


def test_session_and_actual_run_keep_original_customer_price_after_plan_change(
    execution_control_plane,
):
    factory, service, scope, context = execution_control_plane
    original = _plan(factory, scope)
    session = service.create_session(context, project_id=scope.project_id)
    first = _admit(service, scope, context, session_id=session)
    changed = _plan(factory, scope, key="team-v2", version=1, rate=250)
    continued = _admit(service, scope, context, session_id=session)
    fresh_session = service.create_session(context, project_id=scope.project_id)
    fresh = _admit(service, scope, context, session_id=fresh_session)
    independent = _admit(service, scope, context)
    with factory() as db:
        assert db.get(ExecutionSessionRecord, session).customer_pricing_snapshot_id == original
        for identity, expected in (
            (first, original),
            (continued, original),
            (fresh, changed),
            (independent, changed),
        ):
            row = db.get(RunRecord, identity)
            assert row.customer_pricing_frozen and row.customer_pricing_snapshot_id == expected
            authority = BillingMeteringAuthority._run_authority(db, identity)
            price = BillingMeteringAuthority._effective_pricing(
                db,
                tenant_id=scope.tenant_id,
                happened=datetime.now(timezone.utc),
                run=authority,
            )
            assert price.id == expected
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0


def test_missing_admission_price_cannot_borrow_a_later_price(execution_control_plane):
    factory, service, scope, context = execution_control_plane
    _plan(factory, scope, priced=False)
    session = service.create_session(context, project_id=scope.project_id)
    _plan(factory, scope, version=1)
    run = _admit(service, scope, context, session_id=session)
    with factory() as db:
        row = db.get(RunRecord, run)
        assert row.customer_pricing_frozen and row.customer_pricing_snapshot_id is None
        with pytest.raises(BillingMeteringError, match="admitted customer pricing"):
            BillingMeteringAuthority._effective_pricing(
                db,
                tenant_id=scope.tenant_id,
                happened=datetime.now(timezone.utc),
                run=BillingMeteringAuthority._run_authority(db, run),
            )


def test_atomic_task_run_uses_original_session_price_without_writing_usage(
    execution_control_plane,
):
    factory, service, scope, context = execution_control_plane
    original = _plan(factory, scope)
    session_id = service.create_session(context, project_id=scope.project_id)
    changed = _plan(factory, scope, key="team-v2", version=1, rate=250)
    service.configure_quota(
        context, project_id=scope.project_id, resource="run_units", limit_units=1
    )
    admission = _task_admission(service, scope, context, session_id)
    with factory() as db:
        run = db.get(RunRecord, admission.run_id)
        assert run.customer_pricing_frozen
        assert run.customer_pricing_snapshot_id == original
        assert run.customer_pricing_snapshot_id != changed
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0


def test_existing_machine_entry_charges_frozen_price_and_replays_one_usage(metering):
    with metering.factory() as db:
        old = db.get(RunRecord, metering.run_id).customer_pricing_snapshot_id
        assert old is not None
    changed = _plan(metering.factory, metering, key="team-v2", version=1, rate=250)
    receipt = _record(metering)
    replay = _record(metering)
    assert receipt.pricing_snapshot_id == old and receipt.pricing_snapshot_id != changed
    assert receipt.customer_charge_minor == 38
    assert replay.receipt_id == receipt.receipt_id and replay.replayed
    with metering.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(PricingSnapshotRecord)) == 2


def test_frozen_price_does_not_bypass_live_subscription_revocation(metering):
    with metering.factory.begin() as db:
        subscription = db.scalar(sa.select(BillingSubscriptionRecord))
        subscription.status = "canceled"
    with pytest.raises(BillingMeteringError) as denied:
        _record(metering)
    assert denied.value.code == "metering_subscription_unavailable"
    with metering.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
