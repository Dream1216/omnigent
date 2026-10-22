from __future__ import annotations

import asyncio
from time import monotonic
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from omnigent.server.schemas import SessionEventInput
from saas.compatibility import bind_runtime_context
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.platform_models import ModelProviderConfigurationRecord
from saas.production import platform_model_gateway as gateway_module
from saas.production.model_run_inference import LiteLLMRunInference
from saas.production.platform_model_gateway import PlatformModelGateway
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_model_run_cancellation import _request, _settings, _state
from tests.saas.test_model_run_evidence import _enable_budget
from tests.saas.test_model_run_evidence_postgresql import _billing_login
from tests.saas.test_model_run_evidence_postgresql import (
    publication_protocol as publication_protocol,
)
from tests.saas.test_model_run_inference import _stream
from tests.saas.test_model_run_inference_postgresql import _run_binding
from tests.saas.test_model_run_inference_postgresql import (
    funded_publication as funded_publication,
)
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@pytest.mark.parametrize("phase", ("headers", "unknown-body", "known-body"))
def test_actual_app_cancel_stops_pending_inference_and_preserves_unknown_hold(
    interactive_postgresql, tmp_path, monkeypatch, record_property, phase
):
    _settings(monkeypatch)
    monkeypatch.setattr(gateway_module, "_RUN_AUTHORITY_TIMEOUT_SECONDS", 5.0)
    fixture, closed, calls, clients = interactive_postgresql, [], [], []
    body, known, times = phase != "headers", phase == "known-body", {}
    f = fixture.base
    with _run_binding(fixture, None) as binding, _billing_login(f) as billing:
        credentials, lease = binding.credentials, binding.lease
        issued = credentials.issue(binding.authorized, lease)
        published = credentials.authorize(credentials.authenticate(issued.value))
        _enable_budget(f.factory)
        with f.factory.begin() as db:
            config = db.get(ModelProviderConfigurationRecord, "deepseek")
            config.monthly_budget_microusd, config.per_tenant_daily_token_limit = (
                1_000_000,
                100_000,
            )
        with f.app.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT current_user=session_user,rolsuper,rolbypassrls "
                "FROM pg_roles WHERE rolname=current_user"
            ).one() == (True, False, False)
        responses = published.configuration["wire_api"] == "openai_responses"

        def cancel():
            with bind_runtime_context(fixture.runtime):
                fixture.service.dispatch(
                    fixture.runtime,
                    fixture.conversation,
                    SessionEventInput.model_validate({"type": "interrupt", "data": {}}),
                    created_by=fixture.runtime.runtime_user_key,
                )
            with f.factory() as db:
                assert db.get(RunRecord, lease.run_id).status == "cancelling"
            times["cancelled"] = monotonic()

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield _stream(responses) if known else b'data: {"choices":[]}\n\n'
                await asyncio.to_thread(cancel)
                await asyncio.Event().wait()

            async def aclose(self):
                closed.append(True)

        async def upstream(request):
            calls.append(request)
            if body:
                return httpx.Response(200, stream=Body())
            await asyncio.to_thread(cancel)
            try:
                await asyncio.Event().wait()
            finally:
                closed.append(True)

        def transport():
            client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
            clients.append(client)
            return client

        gateway = PlatformModelGateway(
            tokens=None,
            configurations=None,
            pricing=None,
            budgets=ModelProviderBudgetAdmissionService(billing),
            run_credentials=credentials,
            run_inference=LiteLLMRunInference(
                "https://litellm.test",
                "isolated-inference-only-not-a-real-key",
                (published.configuration["deployment_alias"],),
                billing,
            ),
            client_factory=transport,
        )
        p = SimpleNamespace(
            f=f,
            lease=lease,
            grant=published,
            issued=issued,
            responses=responses,
            gateway=gateway,
        )
        call = uuid4()
        result = asyncio.run(_request(p, call, timeout=10))
        elapsed = monotonic() - times["cancelled"]
        record_property("durable_cancel_to_response_seconds", round(elapsed, 3))
        assert elapsed < 6.1
        assert result.status_code == (200 if body else 403), (result.text, len(calls), closed)
        assert closed and len(calls) == 1 and all(client.is_closed for client in clients)
        assert _state(p, call) == (("settled", 13, 0) if known else ("uncertain", 0, 0))
        denied = asyncio.run(_request(p, uuid4(), timeout=10))
        assert denied.status_code == 403 and len(calls) == 1
        assert (result.content == _stream(responses)) is known
