from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_deployments import compile_stored_model_deployment
from saas.control_plane.model_routing_models import (
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelVerificationBudgetBindingRecord,
    ModelVerificationReceiptRecord,
)
from saas.control_plane.model_test_funding import ModelTestFundingPolicy, ModelTestFundingService
from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    ModelProviderMonthlyBudgetRecord,
)
from saas.control_plane.platform_security import PlatformAuthorizationService
from saas.production.model_protocol_probe import (
    ModelProtocolProbe,
    ModelProtocolProbeConfiguration,
)
from saas.production.model_verification import ModelVerificationPublisher
from tests.saas.test_model_protocol_probe import _body, _events
from tests.saas.test_model_verifications import _pricing, _verification_fixture


def _worker_fixture(*, responses=False, inference=None, management_handler=None):
    prices = _pricing()
    prices = replace(
        prices,
        prices=(
            replace(
                prices.prices[0],
                peak_input_cache_hit_microusd_per_million_tokens=500_000,
                peak_input_cache_miss_microusd_per_million_tokens=1_000_000,
                peak_output_microusd_per_million_tokens=2_000_000,
                off_peak_input_cache_hit_microusd_per_million_tokens=500_000,
                off_peak_input_cache_miss_microusd_per_million_tokens=1_000_000,
                off_peak_output_microusd_per_million_tokens=2_000_000,
            ),
        ),
    )
    service, factory, actor, request, _connections = _verification_fixture(
        pricing=prices, wire_api="openai_responses" if responses else "openai_chat_completions"
    )
    funding = ModelTestFundingService(
        factory.kw["bind"], authorization=PlatformAuthorizationService(factory)
    )
    funding.configure(
        actor,
        expected_version=1,
        policy=ModelTestFundingPolicy(True, 2000, 2000, 10000, 2000, 1056, 10),
    )
    request["expected_funding_policy_version"] = 2
    operation = service.admit(actor, **request)
    with factory() as db:
        draft = compile_stored_model_deployment(
            db.get(ModelDeploymentVersionRecord, request["deployment_id"])
        )
        credential_name = db.scalar(
            sa.text("SELECT credential_name FROM saas_model_credential_versions")
        )
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(operation.id)
            )
        )
        envelope = {
            "event_id": event.id,
            **{
                name: getattr(event, name)
                for name in ("event_type", "aggregate_type", "aggregate_key", "payload")
            },
        }
    calls = []

    def manage(request):
        calls.append(request.url.path)
        if management_handler is not None:
            response = management_handler(request)
            if response is not None:
                return response
        if request.url.path == "/model/info":
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "model_name": draft.alias,
                            "model_info": {"id": str(draft.deployment_id)},
                            "litellm_params": {
                                "model": "deepseek/" + draft.public_model_id,
                                "api_base": "https://api.deepseek.com",
                                "litellm_credential_name": credential_name,
                                "num_retries": 0,
                                "max_retries": 0,
                            },
                        }
                    ]
                },
            )
        assert request.url.path == "/key/generate"
        payload = json.loads(request.content)
        assert payload["models"] == [draft.alias] and payload["duration"] == "120s"
        return httpx.Response(200, json={"key": "isolated-verification-inference-key"})

    def infer(request):
        calls.append(request.url.path)
        assert request.headers["authorization"] == "Bearer isolated-verification-inference-key"
        payload = json.loads(request.content)
        assert payload.get("max_tokens", payload.get("max_output_tokens")) == 32
        with factory() as db:
            assert db.get(ModelProjectionOperationRecord, operation.id).status == "applying"
            assert db.scalar(sa.select(ModelProviderBudgetReservationRecord.status)) == "in_flight"
            assert db.get(ModelVerificationBudgetBindingRecord, operation.id) is not None
        if inference is not None:
            return inference(request)
        return httpx.Response(
            200, headers={"Content-Type": "text/event-stream"}, content=_body(_events(draft))
        )

    budget = ModelProviderBudgetAdmissionService(factory)
    publisher = ModelVerificationPublisher(
        factory.kw["bind"],
        management=LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url="https://litellm.test",
                management_key="isolated-verification-management-key",
            ),
            transport=httpx.MockTransport(manage),
        ),
        budget=budget,
        probe=ModelProtocolProbe(
            ModelProtocolProbeConfiguration(base_url="https://litellm.test"),
            transport=httpx.MockTransport(infer),
        ),
    )
    return publisher, envelope, budget, factory, service, actor, operation, calls


@pytest.mark.parametrize("responses", (False, True))
def test_priced_test_settles_actual_usage_once_and_redelivery_never_infers(responses):
    publisher, envelope, _budget, factory, service, actor, operation, calls = _worker_fixture(
        responses=responses
    )
    publisher.publish(**envelope)
    publisher.publish(**envelope)
    assert calls == [
        "/model/info",
        "/key/generate",
        "/v1/responses" if responses else "/v1/chat/completions",
    ]
    receipt = service.receipt(actor, operation.id)
    assert receipt["operation"]["status"] == "verified" and receipt["runtime_enabled"] is False
    evidence = receipt["evidence"]
    assert evidence["usage"]["total_tokens"] == 13 and evidence["actual_microusd"] == 14
    assert evidence["request_attempts"] == 1
    with factory() as db:
        hold = db.scalar(sa.select(ModelProviderBudgetReservationRecord))
        assert (
            hold.status == "settled" and hold.settled_microusd == 14 and hold.released_microusd > 0
        )
        assert (
            hold.outcome_evidence_sha256
            == db.get(ModelVerificationReceiptRecord, operation.id).evidence_sha256
        )
        assert db.scalar(sa.text("SELECT COUNT(*) FROM saas_customer_ledger_entries")) == 0


@pytest.mark.parametrize("status", (401, 429, 500))
def test_supplier_failures_retain_unknown_cost_and_never_instruct_cli_login(status):
    publisher, envelope, budget, factory, service, actor, operation, calls = _worker_fixture(
        inference=lambda _: httpx.Response(status, json={"error": "private-upstream-key-or-body"})
    )
    publisher.publish(**envelope)
    publisher.publish(**envelope)
    receipt = service.receipt(actor, operation.id)
    assert (
        receipt["operation"]["status"] == "uncertain"
        and receipt["evidence"]["actual_microusd"] is None
    )
    assert "private-upstream" not in json.dumps(
        receipt, default=str
    ) and "codex login" not in json.dumps(receipt, default=str)
    assert calls.count("/v1/chat/completions") == 1
    assert budget.recover_expired(now=datetime.now(timezone.utc) + timedelta(days=1)) == ()
    with factory() as db:
        assert db.scalar(sa.select(ModelProviderBudgetReservationRecord.status)) == "uncertain"


def test_monthly_denial_never_mints_key_or_calls_supplier():
    publisher, envelope, budget, _factory, service, actor, operation, calls = _worker_fixture()
    budget.reserve_platform_test(
        verification_id=uuid4(),
        actor_principal_id=actor.principal_id,
        configuration_sha256="f" * 64,
        operation_key="pre-existing-legitimate-hold",
        requested_microusd=1000,
        requested_tokens=1,
        ttl=timedelta(minutes=2),
    )
    publisher.publish(**envelope)
    assert calls == ["/model/info"]
    receipt = service.receipt(actor, operation.id)
    assert (
        receipt["operation"]["status"] == "failed" and receipt["evidence"]["request_attempts"] == 0
    )
    assert receipt["evidence"]["actual_microusd"] == 0


def test_settlement_failure_recovers_from_receipt_without_inference_replay(monkeypatch):
    publisher, envelope, budget, factory, service, actor, operation, calls = _worker_fixture()
    original = budget.resolve_attempt
    count = 0

    def transient(**kwargs):
        nonlocal count
        count += 1
        if count == 1:
            raise RuntimeError("isolated billing availability failure")
        return original(**kwargs)

    monkeypatch.setattr(budget, "resolve_attempt", transient)
    with pytest.raises(RuntimeError, match="billing availability"):
        publisher.publish(**envelope)
    with factory() as db:
        assert db.get(ModelVerificationReceiptRecord, operation.id).outcome == "passed"
        assert db.get(ModelProjectionOperationRecord, operation.id).status == "applying"
    publisher.publish(**envelope)
    assert service.receipt(actor, operation.id)["operation"]["status"] == "verified"
    assert calls.count("/v1/chat/completions") == 1


def test_lost_receipt_persistence_never_replays_upstream(monkeypatch):
    publisher, envelope, _budget, factory, service, actor, operation, calls = _worker_fixture()
    original = publisher._write_receipt

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("isolated receipt database unavailable")

    monkeypatch.setattr(publisher, "_write_receipt", unavailable)
    with pytest.raises(RuntimeError):
        publisher.publish(**envelope)
    monkeypatch.setattr(publisher, "_write_receipt", original)
    publisher.publish(**envelope)
    assert calls.count("/v1/chat/completions") == 1
    assert service.receipt(actor, operation.id)["operation"]["status"] == "uncertain"
    with factory() as db:
        assert db.scalar(sa.select(ModelProviderBudgetReservationRecord.status)) == "uncertain"


def test_redelivery_during_inference_fences_verification_but_retains_real_cost():
    active = {}

    def redeliver(_request):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(active["publisher"].publish, **active["envelope"]).result(timeout=10)
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=_body(_events(active["draft"])),
        )

    publisher, envelope, _budget, factory, service, actor, operation, calls = _worker_fixture(
        inference=redeliver
    )
    with factory() as db:
        draft = compile_stored_model_deployment(
            db.get(ModelDeploymentVersionRecord, operation.deployment_version_id)
        )
    active.update(publisher=publisher, envelope=envelope, draft=draft)
    publisher.publish(**envelope)
    assert service.receipt(actor, operation.id)["operation"]["status"] == "uncertain"
    with factory() as db:
        assert db.scalar(sa.select(ModelProviderBudgetReservationRecord.status)) == "settled"
        assert db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd)) == 14
    assert calls.count("/v1/chat/completions") == 1


def test_cancelled_inference_retains_held_budget_and_records_uncertain():
    def cancelled(_request):
        raise asyncio.CancelledError

    publisher, envelope, _budget, _factory, service, actor, operation, calls = _worker_fixture(
        inference=cancelled
    )
    with pytest.raises(asyncio.CancelledError):
        publisher.publish(**envelope)
    assert service.receipt(actor, operation.id)["operation"]["status"] == "uncertain"
    publisher.publish(**envelope)
    assert calls.count("/v1/chat/completions") == 1
