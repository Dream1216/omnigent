from __future__ import annotations

import json
from dataclasses import replace
from datetime import timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.billing import BillingControlPlane
from saas.control_plane.billing_metering import BillingMeteringAuthority, BillingMeteringError
from saas.control_plane.billing_models import (
    BillingMeteringReceiptRecord,
    BillingSubscriptionRecord,
    UsageEventRecord,
)
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_gateway_metering import gateway_call_reservation_id
from saas.control_plane.model_test_funding import ModelTestFundingService
from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
)
from saas.control_plane.platform_security import PlatformAuthorizationService
from saas.production.model_run_inference import LiteLLMRunInference
from saas.production.platform_model_gateway import (
    PlatformModelGateway,
    create_platform_model_gateway_app,
)
from tests.saas.test_gateway_machine_metering import (
    _customer_prices,
    _register_metering_certificate,
)
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runtime import _running_lease, _runtime_authority
from tests.saas.test_model_run_credentials import _service
from tests.saas.test_model_run_evidence import _enable_budget
from tests.saas.test_model_run_gateway import _document
from tests.saas.test_platform_model_gateway import _parallel_tool_history

pytestmark = pytest.mark.parametrize("interactive_http", [False, True], indirect=True)


def _fund_synthetic_gateway_calls(factory, actor):
    service = ModelTestFundingService(
        factory.kw["bind"], authorization=PlatformAuthorizationService(factory)
    )
    current = service.get(actor)
    service.configure(
        actor,
        expected_version=current.version,
        policy=replace(current.policy, monthly_budget_microusd=1_000_000),
    )


def _stream(responses, *, usage=True):
    if responses:
        row = {
            "type": "response.completed",
            "response": {"id": "resp_synthetic", "status": "completed"},
        }
        if usage:
            row["response"]["usage"] = {
                "input_tokens": 10,
                "output_tokens": 3,
                "total_tokens": 13,
                "input_tokens_details": {"cached_tokens": 0},
            }
        return ("data: " + json.dumps(row) + "\n\n").encode()
    frame = {
        "choices": [],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 3,
            "total_tokens": 13,
            "prompt_cache_hit_tokens": 0,
            "prompt_cache_miss_tokens": 10,
        },
    }
    return (
        ("data: " + json.dumps(frame) + "\n\n") if usage else ""
    ).encode() + b"data: [DONE]\n\n"


async def _setup(f, tmp_path, *, usage=True):
    _fund_synthetic_gateway_calls(f.factory, f.publication_actor)
    _customer_prices(f.factory, actor=f.runtime.actor_id, tenant=f.runtime.tenant_id)
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority)
    issued = service.issue(await authority.authorize(lease), lease)
    grant = service.authorize(service.authenticate(issued.value))
    certificates, fingerprint = _register_metering_certificate(
        f.factory, connection.runner_id, connection.connection_generation, tmp_path
    )
    _enable_budget(f.factory)
    with f.factory.begin() as db:
        configuration = db.get(ModelProviderConfigurationRecord, "deepseek")
        configuration.monthly_budget_microusd = 1_000_000
        configuration.per_tenant_daily_token_limit = 100_000
    budgets = ModelProviderBudgetAdmissionService(f.factory)
    calls = []
    responses = grant.configuration["wire_api"] == "openai_responses"

    def upstream(request):
        calls.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(_stream(responses, usage=usage)))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("managed inference entered the legacy gateway")

    legacy = SimpleNamespace(validate=forbidden, load=forbidden)
    inference = LiteLLMRunInference(
        "https://litellm.test",
        "isolated-inference-only-not-a-real-key",
        (grant.configuration["deployment_alias"],),
        f.factory,
    )
    gateway = PlatformModelGateway(
        tokens=legacy,
        configurations=legacy,
        budgets=budgets,
        pricing=legacy,
        run_credentials=service,
        run_inference=inference,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
    )
    return SimpleNamespace(
        f=f,
        lease=lease,
        connection=connection,
        authority=authority,
        service=service,
        issued=issued,
        grant=grant,
        certificates=certificates,
        fingerprint=fingerprint,
        budgets=budgets,
        calls=calls,
        responses=responses,
        gateway=gateway,
    )


@pytest.mark.asyncio
async def test_real_run_http_inference_and_existing_customer_meter_share_one_call(
    interactive_http, tmp_path
):
    p = await _setup(interactive_http, tmp_path)
    call = uuid4()
    reservation = gateway_call_reservation_id(p.lease.run_id, call)
    meter = BillingMeteringAuthority(p.f.factory)
    identity = {
        "runner_id": p.connection.runner_id,
        "run_id": p.lease.run_id,
        "capability_token": p.lease.capability_token,
        "certificate_fingerprint_sha256": p.fingerprint,
        "reservation_id": reservation,
    }
    assert meter.gateway_usage(action="check", **identity)["status"] == "ready"
    body = _document(p.grant.configuration["public_model_id"], responses=p.responses, limit=32)
    history = _parallel_tool_history()
    if p.responses:
        body["input"] = history
    path = "/v1/responses" if p.responses else "/v1/chat/completions"
    headers = {"Authorization": "Bearer " + p.issued.value, "X-Omnigent-Gateway-Call": str(call)}
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        response = client.post(path, json=body, headers=headers)
        assert response.status_code == 200, response.text
        assert response.content == _stream(p.responses)
        assert client.post(path, json=body, headers=headers).status_code == 409
    assert len(p.calls) == 1
    sent = json.loads(p.calls[0].content)
    assert sent["model"] == p.grant.configuration["deployment_alias"]
    if p.responses:
        assert sent["input"] == [history[index] for index in (0, 1, 2, 3, 7, 4, 5, 6, 8)]
    assert p.calls[0].headers["Authorization"] == "Bearer isolated-inference-only-not-a-real-key"
    assert p.issued.value not in str(p.calls[0].headers)
    assert (sent["max_output_tokens"] if p.responses else sent["max_tokens"]) == 32
    result = meter.gateway_usage(action="settle", **identity)
    assert len(result["receipt_ids"]) == 2
    assert meter.gateway_usage(action="settle", **identity) == result
    with p.f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(BillingMeteringReceiptRecord)) == 2
        assert db.scalar(sa.select(sa.func.sum(UsageEventRecord.customer_charge_minor))) == 2
        budget = db.get(ModelProviderBudgetReservationRecord, reservation)
        assert (
            budget.run_id == p.lease.run_id
            and budget.status == "settled"
            and budget.settled_tokens == 13
        )


@pytest.mark.asyncio
async def test_customer_financial_denial_precedes_egress_and_reference_is_required(
    interactive_http, tmp_path
):
    p = await _setup(interactive_http, tmp_path)
    path = "/v1/responses" if p.responses else "/v1/chat/completions"
    body = _document(p.grant.configuration["public_model_id"], responses=p.responses, limit=32)
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        assert (
            client.post(
                path, json=body, headers={"Authorization": "Bearer " + p.issued.value}
            ).status_code
            == 400
        )
        with p.f.factory() as db:
            s = db.scalar(sa.select(BillingSubscriptionRecord))
            version, plan = s.version, s.plan_key
            start, end = (
                s.current_period_start.replace(tzinfo=timezone.utc),
                s.current_period_end.replace(tzinfo=timezone.utc),
            )
        BillingControlPlane(p.f.factory).configure_subscription(
            actor_id=p.f.runtime.actor_id,
            tenant_id=p.f.runtime.tenant_id,
            plan_key=plan,
            status="canceled",
            current_period_start=start,
            current_period_end=end,
            expected_version=version,
            idempotency_key="cancel-before-inference",
        )
        response = client.post(
            path,
            json=body,
            headers={
                "Authorization": "Bearer " + p.issued.value,
                "X-Omnigent-Gateway-Call": str(uuid4()),
            },
        )
        assert (
            response.status_code == 403
            and response.json()["error"]["code"] == "platform_model_customer_billing_unavailable"
        )
    assert p.calls == []
    with p.f.factory() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ModelProviderBudgetReservationRecord)
                .where(ModelProviderBudgetReservationRecord.purpose == "tenant_run")
            )
            == 0
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0


@pytest.mark.asyncio
async def test_unknown_stream_keeps_reference_and_never_estimates_customer_fee(
    interactive_http, tmp_path
):
    p = await _setup(interactive_http, tmp_path, usage=False)
    call = uuid4()
    reservation = gateway_call_reservation_id(p.lease.run_id, call)
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        response = client.post(
            "/v1/responses" if p.responses else "/v1/chat/completions",
            json=_document(
                p.grant.configuration["public_model_id"], responses=p.responses, limit=32
            ),
            headers={
                "Authorization": "Bearer " + p.issued.value,
                "X-Omnigent-Gateway-Call": str(call),
            },
        )
        assert response.status_code == 200
    with pytest.raises(BillingMeteringError) as error:
        BillingMeteringAuthority(p.f.factory).gateway_usage(
            action="settle",
            runner_id=p.connection.runner_id,
            capability_token=p.lease.capability_token,
            certificate_fingerprint_sha256=p.fingerprint,
            run_id=p.lease.run_id,
            reservation_id=reservation,
        )
    assert error.value.code == "metering_gateway_evidence_unavailable"
    with p.f.factory() as db:
        assert db.get(ModelProviderBudgetReservationRecord, reservation).status == "uncertain"
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
    assert len(p.calls) == 1


@pytest.mark.asyncio
async def test_closed_pre_send_failure_reconciles_without_inventing_usage(
    interactive_http, tmp_path
):
    p = await _setup(interactive_http, tmp_path)
    call = uuid4()

    def failed_transport():
        raise OSError("isolated client setup failure before send")

    p.gateway._client_factory = failed_transport
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        response = client.post(
            "/v1/responses" if p.responses else "/v1/chat/completions",
            json=_document(
                p.grant.configuration["public_model_id"], responses=p.responses, limit=32
            ),
            headers={
                "Authorization": "Bearer " + p.issued.value,
                "X-Omnigent-Gateway-Call": str(call),
            },
        )
        assert response.status_code == 503
    result = BillingMeteringAuthority(p.f.factory).gateway_usage(
        action="settle",
        runner_id=p.connection.runner_id,
        run_id=p.lease.run_id,
        capability_token=p.lease.capability_token,
        certificate_fingerprint_sha256=p.fingerprint,
        reservation_id=gateway_call_reservation_id(p.lease.run_id, call),
    )
    assert result["receipt_ids"] == [] and not p.calls
    with p.f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
