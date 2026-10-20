from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from importlib import import_module
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.billing_models import UsageEventRecord
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.model_budget import (
    ModelProviderBudgetAdmissionService,
    ModelProviderBudgetError,
)
from saas.control_plane.model_gateway_evidence import (
    GatewayRequestEvidence,
    GatewayRunRequestEvidence,
    canonical_gateway_evidence,
    retained_gateway_request,
)
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
    ModelProviderMonthlyBudgetRecord,
)
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runtime import _running_lease, _runtime_authority
from tests.saas.test_model_run_credentials import _service


def _enable_budget(factory):
    from saas.control_plane.platform_models import PlatformStaffPrincipalRecord

    with factory.begin() as db:
        actor = db.scalar(sa.select(PlatformStaffPrincipalRecord.id))
        assert db.get(ModelProviderConfigurationRecord, "deepseek") is None
        db.add(
            ModelProviderConfigurationRecord(
                provider_id="deepseek",
                enabled=True,
                base_url="https://api.deepseek.com",
                api_type="openai_chat_completions",
                api_key_ciphertext="isolated-not-a-key",
                allowed_models=["deepseek-flash"],
                default_model="deepseek-flash",
                monthly_budget_microusd=10_000,
                per_tenant_daily_token_limit=10_000,
                verification_status="verified",
                version=7,
                updated_by_principal_id=actor,
                updated_at=datetime.now(timezone.utc),
            )
        )


def _reserve(budgets, grant, *, operation_key="real-run-evidence"):
    request = grant.gateway_request(output_token_limit=32)
    return budgets.reserve(
        tenant_id=grant.claims.tenant_id,
        run_id=grant.claims.run_id,
        operation_key=operation_key,
        requested_tokens=64,
        requested_microusd=(64 * request.model_price.reservation_rate + 999_999) // 1_000_000,
        ttl=timedelta(minutes=5),
        gateway_request=request,
    )


@pytest.mark.parametrize("interactive_http", [False, True], indirect=True)
@pytest.mark.asyncio
async def test_genuine_run_evidence_retains_frozen_identity_and_cost_but_does_not_charge(
    interactive_http,
):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority)
    issued = service.issue(await authority.authorize(lease), lease)
    grant = service.authorize(service.authenticate(issued.value))
    _enable_budget(f.factory)
    budgets = ModelProviderBudgetAdmissionService(f.factory)
    hold = _reserve(budgets, grant)
    assert hold.status == "reserved" and _reserve(budgets, grant).replayed
    assert hold.run_id == lease.run_id
    request = grant.gateway_request(output_token_limit=32)
    with f.factory() as db:
        run = db.get(RunRecord, lease.run_id)
        assert request.run_binding.session_id == str(run.session_id)
        assert request.run_binding.run_id != request.run_binding.session_id
        assert request.run_binding.customer_pricing_snapshot_id == str(
            run.customer_pricing_snapshot_id
        )
        first = db.scalar(
            sa.select(ModelGatewayEvidenceRecord).where(
                ModelGatewayEvidenceRecord.reservation_id == hold.id,
            )
        )
        assert (
            retained_gateway_request(first, db.get(ModelProviderBudgetReservationRecord, hold.id))
            == request
        )
        document = json.loads(first.canonical_evidence)
        assert document["contract"] == "platform-model-gateway-evidence-v2"
        assert document["run_id"] == str(lease.run_id) and "session_id" not in document
        assert document["request"]["run_binding"] == asdict(request.run_binding)
        assert issued.value not in first.canonical_evidence
        assert "Synthetic" not in first.canonical_evidence
    budgets.begin_attempt(reservation_id=hold.id)
    budgets.mark_uncertain(reservation_id=hold.id)
    # Late provider facts settle the original request, not a revived user Run.
    ExecutionControlPlane(f.factory).transition_run(
        run_id=lease.run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        target_status="succeeded",
        trace_id="isolated-model-evidence",
    )
    usage = ModelTokenUsage(10, 0, 10, 3, 13)
    now = datetime.now(timezone.utc)
    actual = request.model_price.cost(usage, at=now)
    values = {
        "reservation_id": hold.id,
        "actual_microusd": actual,
        "actual_tokens": 13,
        "evidence_sha256": None,
        "gateway_usage": usage,
    }
    assert not budgets.resolve_attempt(**values).replayed
    assert budgets.resolve_attempt(**values).replayed
    facts = budgets.gateway_evidence(
        reservation_id=hold.id, tenant_id=hold.tenant_id, run_id=hold.run_id
    )
    assert [fact.phase for fact in facts] == ["request", "in_flight", "uncertain", "settled"]
    assert all(
        json.loads(fact.canonical_evidence)["contract"] == "platform-model-gateway-evidence-v2"
        for fact in facts
    )
    with f.factory() as db:
        assert db.get(RunRecord, lease.run_id).status == "succeeded"
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == "model_gateway.evidence_retained")
            )
            == 4
        )
        assert db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd)) >= actual
    with pytest.raises(ModelProviderBudgetError):
        budgets.reserve(
            tenant_id=hold.tenant_id,
            run_id=uuid4(),
            operation_key="wrong-run",
            requested_microusd=128,
            requested_tokens=64,
            ttl=timedelta(minutes=1),
            gateway_request=request,
        )


@pytest.mark.parametrize("interactive_http", [False, True], indirect=True)
@pytest.mark.asyncio
async def test_run_evidence_idempotency_binds_all_authority_and_v1_hash_material_stays_unchanged(
    interactive_http,
):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority)
    issued = service.issue(await authority.authorize(lease), lease)
    grant = service.authorize(service.authenticate(issued.value))
    request = grant.gateway_request(output_token_limit=32)
    assert isinstance(request, GatewayRunRequestEvidence)
    legacy = GatewayRequestEvidence(
        request.public_model_id,
        request.wire_api,
        request.pricing_revision,
        request.model_price,
        32,
    )
    assert set(asdict(legacy)) == {
        "public_model_id",
        "wire_api",
        "pricing_revision",
        "model_price",
        "output_token_limit",
    }
    assert canonical_gateway_evidence(asdict(legacy)) == canonical_gateway_evidence(
        {
            "public_model_id": legacy.public_model_id,
            "wire_api": legacy.wire_api,
            "pricing_revision": legacy.pricing_revision,
            "model_price": asdict(legacy.model_price),
            "output_token_limit": 32,
        }
    )
    _enable_budget(f.factory)
    budgets = ModelProviderBudgetAdmissionService(f.factory)
    hold = _reserve(budgets, grant)
    for name, value in (
        ("session_id", str(uuid4())),
        ("capability_id", str(uuid4())),
        ("customer_pricing_snapshot_id", str(uuid4())),
        ("fence_token", 2),
        ("model_token_id", str(uuid4())),
        ("publication_snapshot_sha256", "e" * 64),
    ):
        altered = replace(request, run_binding=replace(request.run_binding, **{name: value}))
        with pytest.raises(ModelProviderBudgetError, match="another request"):
            budgets.reserve(
                tenant_id=hold.tenant_id,
                run_id=hold.run_id,
                operation_key="real-run-evidence",
                requested_microusd=hold.requested_microusd,
                requested_tokens=hold.requested_tokens,
                ttl=timedelta(minutes=5),
                gateway_request=altered,
            )
    with pytest.raises(ValueError):
        grant.gateway_request(output_token_limit=True)


def test_downgrade_checks_the_contract_not_a_legacy_model_name(monkeypatch):
    migration = import_module(
        "saas.control_plane.migrations.versions.lm2g00000001_gateway_run_evidence"
    )
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as db:
            db.execute(
                sa.text("CREATE TABLE saas_model_gateway_evidence(canonical_evidence TEXT)")
            )
            db.execute(
                sa.text("INSERT INTO saas_model_gateway_evidence VALUES (:value)"),
                {
                    "value": json.dumps(
                        {
                            "contract": "platform-model-gateway-evidence-v1",
                            "request": {
                                "public_model_id": "platform-model-gateway-evidence-v2",
                            },
                        }
                    ),
                },
            )
            monkeypatch.setattr(migration.op, "get_bind", lambda: db)
            migration.downgrade()
            db.execute(
                sa.text("INSERT INTO saas_model_gateway_evidence VALUES (:value)"),
                {
                    "value": json.dumps({"contract": "platform-model-gateway-evidence-v2"}),
                },
            )
            with pytest.raises(RuntimeError, match="retained Run gateway evidence"):
                migration.downgrade()
    finally:
        engine.dispose()
