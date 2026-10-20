from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.db_models import ProjectMembershipRecord
from saas.control_plane.platform_models import ModelProviderBudgetReservationRecord
from saas.production.platform_model_gateway import (
    PlatformModelGateway,
    create_platform_model_gateway_app,
)
from saas.production.platform_model_relay import PlatformModelRelay
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runtime import _running_lease, _runtime_authority
from tests.saas.test_model_run_credentials import _service

pytestmark = pytest.mark.parametrize("interactive_http", [False, True], indirect=True)


def _gateway(service, at):
    accessed = []

    def forbidden(*_args, **_kwargs):
        accessed.append("legacy_authority_or_egress")
        raise AssertionError("managed Run entered the legacy route")

    legacy = SimpleNamespace(validate=forbidden, load=forbidden, reserve=forbidden)
    gateway = PlatformModelGateway(
        tokens=legacy,
        configurations=legacy,
        budgets=legacy,
        pricing=legacy,
        client_factory=forbidden,
        run_credentials=service,
        clock=lambda: at[0],
    )
    return TestClient(create_platform_model_gateway_app(gateway)), accessed


def _document(model, *, responses=False, limit=1):
    document = {"model": model, "stream": True}
    if responses:
        document["input"] = "Synthetic gateway authorization probe"
        if limit is not None:
            document["max_output_tokens"] = limit
    else:
        document["messages"] = [
            {"role": "user", "content": "Synthetic gateway authorization probe"}
        ]
        if limit is not None:
            document["max_tokens"] = limit
    return document


@pytest.mark.asyncio
async def test_real_run_gateway_checks_frozen_fields_without_legacy_budget_or_egress(
    interactive_http,
):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    admitted = await authority.authorize(lease)
    service = _service(f, authority)
    issued = service.issue(admitted, lease)
    grant = service.authorize(service.authenticate(issued.value))
    maximum = grant.configuration["max_output_tokens"]
    assert isinstance(maximum, int)
    model = grant.configuration["public_model_id"]
    responses = grant.configuration["wire_api"] == "openai_responses"
    path = "/v1/responses" if responses else "/v1/chat/completions"
    client, accessed = _gateway(service, [datetime.now(timezone.utc)])
    provider_calls = list(f.calls)
    with f.factory() as db:
        original_budget_count = db.scalar(
            sa.select(sa.func.count()).select_from(ModelProviderBudgetReservationRecord)
        )
    try:
        for body, status, code in (
            (
                _document(model, responses=responses),
                503,
                "platform_model_run_execution_unavailable",
            ),
            (
                _document(model, responses=responses, limit=None),
                503,
                "platform_model_run_execution_unavailable",
            ),
            (_document("other-model", responses=responses), 400, "platform_model_not_allowed"),
            (
                _document(model, responses=responses, limit=maximum + 1),
                400,
                "platform_model_output_limit_exceeded",
            ),
            (
                {**_document(model, responses=responses), "api_key": "caller-cannot-route"},
                400,
                "platform_model_request_invalid",
            ),
        ):
            response = client.post(
                path, json=body, headers={"Authorization": "Bearer " + issued.value}
            )
            assert response.status_code == status and response.json()["error"]["code"] == code
        wrong_path = "/v1/chat/completions" if responses else "/v1/responses"
        response = client.post(
            wrong_path,
            json=_document(model, responses=not responses),
            headers={"Authorization": "Bearer " + issued.value},
        )
        assert (
            response.status_code == 400
            and response.json()["error"]["code"] == "platform_model_not_allowed"
        )
        assert accessed == [] and f.calls == provider_calls
        with f.factory() as db:
            assert (
                db.scalar(
                    sa.select(sa.func.count()).select_from(ModelProviderBudgetReservationRecord)
                )
                == original_budget_count
            )
    finally:
        client.close()


@pytest.mark.asyncio
async def test_only_authentic_expiry_gets_the_recovery_error_and_revocation_is_not_expiry(
    interactive_http,
):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority, ttl=timedelta(seconds=10))
    now = datetime.now(timezone.utc)
    issued = service.issue(await authority.authorize(lease), lease, now=now)
    at = [now + timedelta(seconds=11)]
    client, accessed = _gateway(service, at)
    path = (
        "/v1/responses" if f.marker["wire_api"] == "openai_responses" else "/v1/chat/completions"
    )
    body = _document(f.marker["public_model_id"], responses=path == "/v1/responses")
    try:
        response = client.post(
            path, json=body, headers={"Authorization": "Bearer " + issued.value}
        )
        assert response.status_code == 401
        assert response.json()["error"] == {
            "code": "platform_model_authentication_expired",
            "message": "会话认证过期，正在恢复",
        }
        response = client.post(
            path, json=body, headers={"Authorization": "Bearer mrt_" + "0" * 64}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "platform_model_authentication_invalid"
        at[0] = now
        with f.factory.begin() as db:
            db.execute(sa.update(ProjectMembershipRecord).values(status="revoked"))
        response = client.post(
            path, json=body, headers={"Authorization": "Bearer " + issued.value}
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "platform_model_run_authority_unavailable"
        assert accessed == []
    finally:
        client.close()


@pytest.mark.asyncio
async def test_managed_namespace_never_falls_back_when_the_service_is_missing(interactive_http):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority)
    issued = service.issue(await authority.authorize(lease), lease)
    client, accessed = _gateway(None, [datetime.now(timezone.utc)])
    try:
        response = client.post(
            "/v1/responses",
            json=_document(f.marker["public_model_id"], responses=True),
            headers={"Authorization": "Bearer " + issued.value},
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "platform_model_run_authority_unavailable"
        assert accessed == []
    finally:
        client.close()


@pytest.mark.asyncio
async def test_real_lease_renewal_reaches_gateway_without_replaying_or_billing(interactive_http):
    from saas.control_plane.execution_models import RunRecord, TaskRecord
    from saas.control_plane.model_routing_models import ModelRunTokenRecord

    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority, ttl=timedelta(seconds=10))
    now = [datetime.now(timezone.utc)]
    minted = []

    async def credentials():
        authorized = await authority.authorize(lease)
        issued = service.issue(authorized, lease, now=now[0])
        minted.append(issued)
        return issued

    gateway, legacy = _gateway(service, now)
    sent = []

    async def observe(request):
        sent.append(request.headers["Authorization"])

    relay = PlatformModelRelay.for_run(
        run_id=lease.run_id,
        fence_token=lease.fence_token,
        credential_provider=credentials,
        ttl_seconds=10,
        clock=lambda: now[0].timestamp(),
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway.app), event_hooks={"request": [observe]}
        ),
    )
    path = (
        "/v1/responses" if f.marker["wire_api"] == "openai_responses" else "/v1/chat/completions"
    )
    body = _document(f.marker["public_model_id"], responses=path == "/v1/responses")
    before = list(f.calls)
    try:
        with TestClient(relay.app) as client:
            headers = {"Authorization": "Bearer " + relay.capability}
            first = client.post(path, json=body, headers=headers)
            assert first.status_code == 503
            assert first.json()["error"]["code"] == "platform_model_run_execution_unavailable"
            now[0] += timedelta(seconds=9.5)
            second = client.post(path, json=body, headers=headers)
            assert second.status_code == 503
            assert second.json()["error"]["code"] == "platform_model_run_execution_unavailable"
            assert len(sent) == 2 and sent[0] != sent[1]
            assert len(minted) == 2 and minted[-1].generation == 1
            assert all(relay.capability not in token for token in sent)
            with f.factory.begin() as db:
                db.execute(sa.update(ProjectMembershipRecord).values(status="revoked"))
            denied = client.post(path, json=body, headers=headers)
            assert denied.status_code == 403 and len(sent) == 3 and len(minted) == 2
        assert f.calls == before and legacy == []
        with f.factory() as db:
            for model, count in ((ModelRunTokenRecord, 2), (RunRecord, 1), (TaskRecord, 1)):
                assert db.scalar(sa.select(sa.func.count()).select_from(model)) == count
    finally:
        gateway.close()
