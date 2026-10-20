from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.billing_models import UsageEventRecord
from saas.control_plane.model_gateway_metering import gateway_call_reservation_id
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord
from saas.control_plane.platform_models import ModelProviderBudgetReservationRecord
from saas.control_plane.tenant_model_catalog import TenantModelCatalogError
from saas.production.platform_model_gateway import create_platform_model_gateway_app
from tests.saas.test_interactive_execution_http import _post
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_model_run_gateway import _document
from tests.saas.test_model_run_inference import _setup, _stream

pytestmark = pytest.mark.parametrize("interactive_http", [False, True], indirect=True)


def _disable(f):
    with f.factory() as db:
        publication = db.scalars(sa.select(ModelPublicationVersionRecord)).one()
    return f.publication_service.disable(
        f.publication_actor,
        publication_id=publication.id,
        expected_generation=publication.generation,
        idempotency_key="disable-runtime-001",
    )


def _request(client, p, call_id):
    return client.post(
        "/v1/responses" if p.responses else "/v1/chat/completions",
        json=_document(p.grant.configuration["public_model_id"], responses=p.responses, limit=32),
        headers={
            "Authorization": "Bearer " + p.issued.value,
            "X-Omnigent-Gateway-Call": str(call_id),
        },
    )


@pytest.mark.asyncio
async def test_disablement_denies_old_model_bearer_and_renewal_but_keeps_interrupt(
    interactive_http, tmp_path
):
    p = await _setup(interactive_http, tmp_path)
    _disable(p.f)
    with pytest.raises(TenantModelCatalogError, match="disabled"):
        p.service.renew(p.issued.value)
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        response = _request(client, p, uuid4())
    assert response.status_code == 403, response.text
    assert p.calls == []
    with p.f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ModelProviderBudgetReservationRecord)
                .where(ModelProviderBudgetReservationRecord.purpose == "tenant_run")
            )
            == 0
        )
    interrupted = _post(p.f, {"type": "interrupt", "data": {}})
    assert interrupted.status_code == 202, interrupted.text


@pytest.mark.asyncio
async def test_promoted_run_gateway_cannot_fall_back_to_legacy_session_authority(
    interactive_http, tmp_path
):
    p = await _setup(interactive_http, tmp_path)
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        response = client.post(
            "/v1/responses" if p.responses else "/v1/chat/completions",
            json=_document(
                p.grant.configuration["public_model_id"], responses=p.responses, limit=32
            ),
            headers={"Authorization": "Bearer legacy-session-not-a-Run-credential"},
        )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "platform_model_legacy_inference_disabled"
    assert p.calls == []


@pytest.mark.asyncio
async def test_cutoff_committed_after_reservation_still_prevents_the_single_send(
    interactive_http, tmp_path, monkeypatch
):
    p = await _setup(interactive_http, tmp_path)
    begin = p.budgets.begin_attempt

    def disable_before_send(**kwargs):
        _disable(p.f)
        return begin(**kwargs)

    monkeypatch.setattr(p.budgets, "begin_attempt", disable_before_send)
    call_id = uuid4()
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        response = _request(client, p, call_id)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "platform_model_disabled"
    assert p.calls == []
    with p.f.factory() as db:
        row = db.get(
            ModelProviderBudgetReservationRecord,
            gateway_call_reservation_id(p.lease.run_id, call_id),
        )
        assert row.status == "released" and row.settled_tokens == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0


@pytest.mark.asyncio
async def test_accepted_call_can_settle_known_usage_after_disablement(interactive_http, tmp_path):
    p = await _setup(interactive_http, tmp_path)

    def already_sent(request):
        p.calls.append(request)
        _disable(p.f)
        return httpx.Response(200, stream=httpx.ByteStream(_stream(p.responses)))

    p.gateway._client_factory = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(already_sent)
    )
    call_id = uuid4()
    with TestClient(create_platform_model_gateway_app(p.gateway)) as client:
        response = _request(client, p, call_id)
        assert response.status_code == 200, response.text
        assert _request(client, p, uuid4()).status_code == 403
    assert len(p.calls) == 1
    result = BillingMeteringAuthority(p.f.factory).gateway_usage(
        action="settle",
        runner_id=p.connection.runner_id,
        run_id=p.lease.run_id,
        capability_token=p.lease.capability_token,
        certificate_fingerprint_sha256=p.fingerprint,
        reservation_id=gateway_call_reservation_id(p.lease.run_id, call_id),
    )
    assert len(result["receipt_ids"]) == 2
    with p.f.factory() as db:
        row = db.get(
            ModelProviderBudgetReservationRecord,
            gateway_call_reservation_id(p.lease.run_id, call_id),
        )
        assert row.status == "settled" and row.settled_tokens == 13
        assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 2
