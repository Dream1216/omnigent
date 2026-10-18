from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from threading import Event
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from starlette.requests import ClientDisconnect

from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.billing_models import UsageEventRecord
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.model_gateway_metering import gateway_call_reservation_id
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
)
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from saas.production import platform_model_gateway as gateway_module
from saas.production.platform_model_gateway import create_platform_model_gateway_app
from tests.saas.test_interactive_execution_http import _post
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_model_disablement_runtime import _disable
from tests.saas.test_model_run_gateway import _document
from tests.saas.test_model_run_inference import _setup, _stream

pytestmark = pytest.mark.parametrize("interactive_http", (False, True), indirect=True)


def _settings(monkeypatch):
    monkeypatch.setattr(gateway_module, "_RUN_AUTHORITY_POLL_SECONDS", 0.05, raising=False)
    monkeypatch.setattr(gateway_module, "_RUN_AUTHORITY_TIMEOUT_SECONDS", 0.1, raising=False)


async def _request(p, call, *, timeout=2):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_platform_model_gateway_app(p.gateway)),
        base_url="https://gateway.test",
    ) as client:
        try:
            return await asyncio.wait_for(
                client.post(
                    "/v1/responses" if p.responses else "/v1/chat/completions",
                    json=_document(
                        p.grant.configuration["public_model_id"], responses=p.responses, limit=32
                    ),
                    headers={
                        "Authorization": "Bearer " + p.issued.value,
                        "X-Omnigent-Gateway-Call": str(call),
                    },
                ),
                timeout=timeout,
            )
        except TimeoutError:
            pytest.fail("Managed inference ignored durable cancellation or authority failure")


def _cancel(p):
    result = _post(p.f, {"type": "interrupt", "data": {}})
    assert result.status_code == 202
    with p.f.factory() as db:
        assert db.get(RunRecord, p.lease.run_id).status == "cancelling"


def _state(p, call):
    with p.f.factory() as db:
        row = db.get(
            ModelProviderBudgetReservationRecord, gateway_call_reservation_id(p.lease.run_id, call)
        )
        if row.status == "uncertain":
            assert row.admitted_tokens > 0 and row.admitted_microusd > 0
            assert row.released_tokens == row.released_microusd == 0
            assert row.outcome_evidence_sha256 is None
            phases = set(
                db.scalars(
                    sa.select(ModelGatewayEvidenceRecord.phase).where(
                        ModelGatewayEvidenceRecord.reservation_id == row.id
                    )
                )
            )
            assert phases == {"request", "in_flight", "uncertain"}
        return (
            row.status,
            row.settled_tokens,
            db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ("cancel", "capability", "fence", "lease"))
async def test_durable_cancel_stops_a_request_waiting_for_supplier_headers(
    interactive_http, tmp_path, monkeypatch, change
):
    _settings(monkeypatch)
    p = await _setup(interactive_http, tmp_path)
    closed = asyncio.Event()

    async def upstream(request):
        p.calls.append(request)
        if change == "cancel":
            _cancel(p)
        else:
            with p.f.factory.begin() as db:
                if change == "capability":
                    capability = db.get(CapabilityTokenRecord, p.lease.capability_id)
                    capability.revoked_at = datetime.now(timezone.utc)
                    capability.revocation_reason = "isolated authority revocation"
                elif change == "fence":
                    db.get(RunRecord, p.lease.run_id).fence_token += 1
                else:
                    db.get(RunRecord, p.lease.run_id).lease_expires_at = datetime.now(
                        timezone.utc
                    ) - timedelta(seconds=1)
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    clients = []

    def transport():
        client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
        clients.append(client)
        return client

    p.gateway._client_factory = transport
    call = uuid4()
    response = await _request(p, call)
    assert response.status_code == 403 and closed.is_set()
    assert response.json()["error"]["code"] == "platform_model_run_authority_unavailable"
    assert len(p.calls) == 1 and all(client.is_closed for client in clients)
    assert _state(p, call) == ("uncertain", 0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("after_usage", (False, True))
async def test_asgi_disconnect_closes_transport_before_iterator_or_after_known_usage(
    interactive_http, tmp_path, monkeypatch, after_usage
):
    _settings(monkeypatch)
    p = await _setup(interactive_http, tmp_path)
    entered, closed, clients = [], asyncio.Event(), []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            entered.append(True)
            yield _stream(p.responses)
            await asyncio.Event().wait()

        async def aclose(self):
            closed.set()

    def upstream(request):
        p.calls.append(request)
        return httpx.Response(200, stream=Body())

    def transport():
        client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
        clients.append(client)
        return client

    p.gateway._client_factory = transport
    call = uuid4()
    document = _document(p.grant.configuration["public_model_id"], responses=p.responses, limit=32)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "method": "POST",
        "path": "/v1/responses" if p.responses else "/v1/chat/completions",
        "query_string": b"",
        "headers": [
            (b"authorization", ("Bearer " + p.issued.value).encode()),
            (b"x-omnigent-gateway-call", str(call).encode()),
            (b"content-type", b"application/json"),
        ],
    }

    async def receive():
        return {"type": "http.request", "body": json.dumps(document).encode()}

    async def send(message):
        if message["type"] == ("http.response.body" if after_usage else "http.response.start"):
            raise OSError("isolated downstream disconnect")

    app = create_platform_model_gateway_app(p.gateway)
    with pytest.raises(ClientDisconnect):
        await asyncio.wait_for(app(scope, receive, send), timeout=2)
    assert bool(entered) == after_usage and closed.is_set()
    assert len(p.calls) == 1 and all(client.is_closed for client in clients)
    assert _state(p, call) == (("settled", 13, 0) if after_usage else ("uncertain", 0, 0))


@pytest.mark.asyncio
@pytest.mark.parametrize("final_usage", (False, True))
async def test_durable_cancel_closes_stalled_body_without_inventing_or_duplicating_usage(
    interactive_http, tmp_path, monkeypatch, final_usage
):
    _settings(monkeypatch)
    p = await _setup(interactive_http, tmp_path)
    closed = asyncio.Event()

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield _stream(p.responses) if final_usage else b'data: {"choices":[]}\n\n'
            _cancel(p)
            await asyncio.Event().wait()

        async def aclose(self):
            closed.set()

    async def upstream(request):
        p.calls.append(request)
        return httpx.Response(200, stream=Body())

    p.gateway._client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    call = uuid4()
    response = await _request(p, call)
    assert response.status_code == 200 and closed.is_set() and len(p.calls) == 1
    if not final_usage:
        assert _state(p, call) == ("uncertain", 0, 0)
    else:
        assert _state(p, call) == ("settled", 13, 0)
        meter = BillingMeteringAuthority(p.f.factory)
        arguments = {
            "action": "settle",
            "runner_id": p.connection.runner_id,
            "run_id": p.lease.run_id,
            "capability_token": p.lease.capability_token,
            "certificate_fingerprint_sha256": p.fingerprint,
            "reservation_id": gateway_call_reservation_id(p.lease.run_id, call),
        }
        first = meter.gateway_usage(**arguments)
        assert len(first["receipt_ids"]) == 2
        assert meter.gateway_usage(**arguments)["receipt_ids"] == first["receipt_ids"]
        assert _state(p, call) == ("settled", 13, 2)


@pytest.mark.asyncio
async def test_ordinary_cutoff_does_not_cancel_an_accepted_stream_during_authority_polls(
    interactive_http, tmp_path, monkeypatch
):
    _settings(monkeypatch)
    p = await _setup(interactive_http, tmp_path)
    check = p.service.require_in_flight
    checks = []

    def checked(*args, **kwargs):
        checks.append(True)
        return check(*args, **kwargs)

    monkeypatch.setattr(p.service, "require_in_flight", checked)

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            _disable(p.f)
            await asyncio.sleep(0.125)
            yield _stream(p.responses)

    def upstream(request):
        p.calls.append(request)
        return httpx.Response(200, stream=Body())

    p.gateway._client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    call = uuid4()
    response = await _request(p, call)
    assert response.status_code == 200 and response.content == _stream(p.responses)
    assert checks and len(p.calls) == 1 and _state(p, call) == ("settled", 13, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", (False, True))
async def test_authority_failure_or_timeout_stops_transport_without_leaking_diagnostics(
    interactive_http, tmp_path, monkeypatch, timeout
):
    _settings(monkeypatch)
    p = await _setup(interactive_http, tmp_path)
    release = Event()
    closed = asyncio.Event()

    def unavailable(*_args, **_kwargs):
        if timeout:
            release.wait(5)
        raise RuntimeError("private authority credentials must not leak")

    monkeypatch.setattr(p.service, "require_in_flight", unavailable)

    async def upstream(request):
        p.calls.append(request)
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    p.gateway._client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    call = uuid4()
    try:
        response = await _request(p, call)
    finally:
        release.set()
    assert response.status_code == 503 and closed.is_set() and len(p.calls) == 1
    assert "private authority" not in response.text and "credentials" not in response.text
    assert _state(p, call) == ("uncertain", 0, 0)
