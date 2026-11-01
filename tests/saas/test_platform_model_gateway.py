from __future__ import annotations

import ast
import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import httpx
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url

from omnigent.debug_logging import PRIMARY_SESSION_ID_ENV_VAR
from omnigent.host.connect import HostProcess
from omnigent.host.identity import HostIdentity
from saas.control_plane.model_budget import ModelProviderBudgetReservationView
from saas.control_plane.model_provider import PlatformManagedModelRuntimeConfiguration
from saas.production.platform_model_gateway import (
    GatewayTokenVerifier,
    PlatformModelGateway,
    PlatformModelPrice,
    PlatformModelPricingPolicy,
    _normalize_responses_tool_history,
    build_platform_model_gateway,
    create_platform_model_gateway_app,
    load_platform_model_pricing,
)
from saas.production.platform_model_host import PlatformModelHostProcess
from saas.production.platform_model_relay import PlatformModelRelay
from saas.production.service_bindings import (
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
)
from saas.production.tenant_model_keys import TenantModelKeyBinding, TenantModelTokenVerifier
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority
from saas.runner_adapter.platform_models import (
    PLATFORM_MODEL_CREDENTIAL_ENV,
    PLATFORM_MODEL_CREDENTIAL_REFERENCE,
    PLATFORM_MODEL_RELAY_BASE_URL_ENV,
    render_platform_model_gateway_config,
)

TENANT_ID = UUID("10000000-0000-0000-0000-000000000001")
SESSION_ID = UUID("20000000-0000-0000-0000-000000000002")
SIGNING_KEY = b"model-gateway-test-signing-key-32-bytes-minimum"
_DEFAULT_CONFIGURATION = object()


class _ConfigurationReader:
    def __init__(self, configuration: PlatformManagedModelRuntimeConfiguration | None) -> None:
        self.configuration = configuration

    def load(self) -> PlatformManagedModelRuntimeConfiguration | None:
        return self.configuration


class _Budgets:
    def __init__(self) -> None:
        self.reserved: list[dict[str, object]] = []
        self.settled: list[dict[str, object]] = []
        self.released: list[dict[str, object]] = []

    def reserve(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        self.reserved.append(kwargs)
        requested_microusd = kwargs["requested_microusd"]
        requested_tokens = kwargs["requested_tokens"]
        assert isinstance(requested_microusd, int)
        assert isinstance(requested_tokens, int)
        return ModelProviderBudgetReservationView(
            id=uuid4(),
            provider_id="deepseek",
            tenant_id=TENANT_ID,
            run_id=SESSION_ID,
            configuration_version=7,
            requested_microusd=requested_microusd,
            requested_tokens=requested_tokens,
            admitted_microusd=requested_microusd,
            admitted_tokens=requested_tokens,
            settled_microusd=0,
            settled_tokens=0,
            released_microusd=0,
            released_tokens=0,
            status="reserved",
            rejection_code=None,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            version=1,
        )

    def settle(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        self.settled.append(kwargs)
        raise_if_called = kwargs.pop("raise_if_called", False)
        assert not raise_if_called
        reservation = self.reserved[-1]
        return self.reserve(**reservation)

    def release(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        self.released.append(kwargs)
        reservation = self.reserved[-1]
        return self.reserve(**reservation)


def _configuration() -> PlatformManagedModelRuntimeConfiguration:
    return PlatformManagedModelRuntimeConfiguration(
        provider_id="deepseek",
        base_url="https://api.deepseek.com",
        api_type="openai_chat_completions",
        allowed_models=("deepseek-flash",),
        default_model="deepseek-flash",
        monthly_budget_microusd=100_000_000,
        per_tenant_daily_token_limit=1_000_000,
        configuration_version=7,
        api_key="provider-secret-never-returned",
    )


def _client(
    handler: httpx.AsyncBaseTransport | httpx.MockTransport,
    *,
    tokens: GatewayTokenVerifier | None = None,
    configuration: PlatformManagedModelRuntimeConfiguration
    | object
    | None = _DEFAULT_CONFIGURATION,
    retry_clock=None,
) -> tuple[TestClient, _Budgets, str]:
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=SIGNING_KEY,
        tenant_id=TENANT_ID,
    )
    budgets = _Budgets()
    gateway = PlatformModelGateway(
        tokens=tokens or authority,
        configurations=_ConfigurationReader(
            _configuration()
            if configuration is _DEFAULT_CONFIGURATION
            else cast(PlatformManagedModelRuntimeConfiguration | None, configuration)
        ),
        budgets=budgets,
        pricing=PlatformModelPricingPolicy(
            revision="pricing-test-20260914",
            catalog_sha256="fc2923d2ab3ac92a2b1b16fef40cbcfbb139c3abcd9f4e7d3b3e3c34a8e8427c",
            prices=(
                PlatformModelPrice(
                    model_sha256="7d963f65d1ede1bd9416a5f55575efe0d202e0a00519ef04e47dae20c3180445",
                    peak_input_cache_hit_microusd_per_million_tokens=6_000,
                    peak_input_cache_miss_microusd_per_million_tokens=300_000,
                    peak_output_microusd_per_million_tokens=1_200_000,
                    off_peak_input_cache_hit_microusd_per_million_tokens=3_000,
                    off_peak_input_cache_miss_microusd_per_million_tokens=150_000,
                    off_peak_output_microusd_per_million_tokens=600_000,
                ),
            ),
        ),
        client_factory=lambda: httpx.AsyncClient(transport=handler),
        clock=lambda: datetime(2026, 9, 14, 0, 30, tzinfo=timezone.utc),
        retry_clock=retry_clock,
    )
    return (
        TestClient(create_platform_model_gateway_app(gateway)),
        budgets,
        authority.issue(session_id=SESSION_ID, now=int(datetime.now(timezone.utc).timestamp())),
    )


def test_streams_provider_bytes_and_settles_observed_usage() -> None:
    async def upstream(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer provider-secret-never-returned"
        sent = __import__("json").loads(request.content)
        assert sent["stream_options"] == {"include_usage": True}
        body = (
            b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":10,'
            b'"prompt_cache_hit_tokens":4,"prompt_cache_miss_tokens":6,'
            b'"completion_tokens":5,"total_tokens":15}}\n\n'
            b"data: [DONE]\n\n"
        )
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 100,
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert b'"content":"hello"' in response.content
    assert budgets.reserved[0]["tenant_id"] == TENANT_ID
    assert budgets.reserved[0]["run_id"] == SESSION_ID
    assert budgets.settled == [
        {
            "reservation_id": budgets.settled[0]["reservation_id"],
            "actual_microusd": 5,
            "actual_tokens": 15,
        }
    ]
    assert not budgets.released


def test_streams_responses_api_and_settles_nested_usage() -> None:
    async def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/responses"
        sent = json.loads(request.content)
        assert sent["stream"] is True
        assert "stream_options" not in sent
        body = (
            b"event: response.output_text.delta\n"
            b'data: {"type":"response.output_text.delta","delta":"hello"}\n\n'
            b"event: response.completed\n"
            b'data: {"type":"response.completed","response":{"usage":'
            b'{"input_tokens":10,"input_tokens_details":{"cached_tokens":4},'
            b'"output_tokens":5,"total_tokens":15}}}\n\n'
        )
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "model": "deepseek-flash",
            "input": "hello",
            "max_output_tokens": 100,
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert b'"delta":"hello"' in response.content
    assert budgets.settled == [
        {
            "reservation_id": budgets.settled[0]["reservation_id"],
            "actual_microusd": 5,
            "actual_tokens": 15,
        }
    ]


def test_responses_accepts_nullable_output_limit() -> None:
    async def upstream(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        assert sent["max_output_tokens"] is None
        body = (
            b"event: response.completed\n"
            b'data: {"type":"response.completed","response":{"usage":'
            b'{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n'
        )
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    client, _budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "model": "deepseek-flash",
            "input": "hello",
            "max_output_tokens": None,
            "stream": True,
        },
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("call_kind", "output_kind"),
    [("function_call", "function_call_output"), ("custom_tool_call", "custom_tool_call_output")],
)
def test_replayed_parallel_results_precede_progress_without_replaying_tools(
    call_kind, output_kind, caplog
):
    history = [
        {"type": "message", "role": "user", "content": "Keep the existing task."},
        {"type": call_kind, "call_id": "slow", "name": "read_file", "arguments": "{}"},
        {"type": call_kind, "call_id": "fast", "name": "read_file", "arguments": "{}"},
        {"type": output_kind, "call_id": "fast", "output": "already completed fast result"},
        {"type": "message", "role": "assistant", "content": "Progress before slow result."},
        {"type": call_kind, "call_id": "later", "name": "read_file", "arguments": "{}"},
        {"type": output_kind, "call_id": "later", "output": "already completed later result"},
        {"type": output_kind, "call_id": "slow", "output": "already completed slow result"},
        {"type": "message", "role": "user", "content": "Continue without repeating tools."},
    ]
    original = json.loads(json.dumps(history))
    observed = []

    async def upstream(request):
        sent = json.loads(request.content)
        observed.append(sent["input"])
        assert sent["input"] == [original[i] for i in (0, 1, 2, 3, 7, 4, 5, 6, 8)]
        return httpx.Response(
            200,
            content=b'data: {"type":"response.completed","response":{"usage":'
            b'{"input_tokens":10,"output_tokens":2,"total_tokens":12}}}\n\n',
        )

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": history, "stream": True},
    )
    assert response.status_code == 200
    assert len(observed) == 1 and len(budgets.settled) == 1 and not budgets.released
    assert history == original
    assert "already completed" not in caplog.text
    assert _normalize_responses_tool_history(observed[0]) is observed[0]


@pytest.mark.parametrize(
    "case",
    ["missing", "duplicate", "orphan", "user-boundary", "unknown-boundary", "kind-mismatch"],
)
def test_history_normalization_does_not_invent_results_or_cross_control_boundaries(case):
    call = {"type": "function_call", "call_id": "one", "name": "read_file", "arguments": "{}"}
    progress = {"type": "message", "role": "assistant", "content": "Still working."}
    output = {"type": "function_call_output", "call_id": "one", "output": "existing result"}
    histories = {
        "missing": [call, progress],
        "duplicate": [call, call, progress, output],
        "orphan": [output, call, progress],
        "user-boundary": [
            call,
            progress,
            {"type": "message", "role": "user", "content": "Stop."},
            output,
        ],
        "unknown-boundary": [call, progress, {"type": "item_reference", "id": "opaque"}, output],
        "kind-mismatch": [call, progress, {**output, "type": "custom_tool_call_output"}],
    }
    history = histories[case]
    original = json.loads(json.dumps(history))
    assert _normalize_responses_tool_history(history) is history
    assert history == original


def test_history_normalization_preserves_valid_and_non_list_inputs():
    for value in (
        None,
        "plain input",
        [],
        [{"type": "message", "role": "user", "content": "hello"}],
    ):
        assert _normalize_responses_tool_history(value) is value


@pytest.mark.parametrize(
    "item", [{"type": []}, {"type": {}}, None, "opaque", {"type": "function_call", "call_id": []}]
)
def test_malformed_history_items_do_not_crash_gateway_normalization(item):
    history = [item]
    assert _normalize_responses_tool_history(history) is history


def test_provider_rejection_releases_budget_without_leaking_body() -> None:
    async def upstream(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "contains-sensitive-provider-detail"})

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "messages": [], "stream": True},
    )

    assert response.status_code == 424
    assert response.json()["error"]["code"] == "platform_model_provider_authentication_failed"
    assert "contains-sensitive-provider-detail" not in response.text
    assert len(budgets.released) == 1
    assert not budgets.settled


@pytest.mark.parametrize(
    ("upstream_status", "expected_status", "code", "retryable"),
    [
        (400, 400, "platform_model_provider_request_invalid", False),
        (422, 422, "platform_model_provider_request_invalid", False),
        (401, 424, "platform_model_provider_authentication_failed", False),
        (403, 424, "platform_model_provider_authentication_failed", False),
        (402, 424, "platform_model_provider_budget_exhausted", False),
        (404, 422, "platform_model_provider_protocol_unavailable", False),
        (405, 422, "platform_model_provider_protocol_unavailable", False),
        (429, 429, "platform_model_provider_rate_limited", True),
        (503, 503, "platform_model_provider_unavailable", True),
    ],
)
def test_provider_failures_are_classified_without_exposing_private_details(
    upstream_status, expected_status, code, retryable, caplog
):
    secret = "provider-secret-never-returned"

    async def upstream(_request):
        return httpx.Response(
            upstream_status,
            json={"error": {"code": secret, "message": "private prompt " + secret}},
            headers={"x-request-id": secret, "retry-after": "12"},
        )

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "private user prompt", "stream": True},
    )

    error = response.json()["error"]
    assert response.status_code == expected_status
    assert error["code"] == code and error["retryable"] is retryable
    assert UUID(error["request_id"]).hex == response.headers["x-request-id"]
    assert error["request_id"] in error["message"]
    assert error["request_id"] in caplog.text
    assert f"provider_status={upstream_status}" in caplog.text
    assert secret not in response.text + caplog.text
    assert "private prompt" not in response.text + caplog.text
    assert "private user prompt" not in response.text + caplog.text
    assert len(budgets.released) == 1 and not budgets.settled
    if upstream_status == 429:
        assert response.headers["retry-after"] == "12"


def test_transient_failures_stop_egress_and_reservations_during_session_cooldown():
    calls = 0
    now = [0.0]

    async def upstream(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    client, budgets, token = _client(httpx.MockTransport(upstream), retry_clock=lambda: now[0])
    headers = {"Authorization": f"Bearer {token}"}
    body = {"model": "deepseek-flash", "input": "hello", "stream": True}
    assert client.post("/v1/responses", headers=headers, json=body).status_code == 503
    assert client.post("/v1/responses", headers=headers, json=body).status_code == 503
    reservations_before = len(budgets.reserved)
    for _ in range(8):
        response = client.post("/v1/responses", headers=headers, json=body)
        assert response.status_code == 424
        assert response.json()["error"]["code"] == "platform_model_retry_cooldown"
        assert response.json()["error"]["retryable"] is False
    assert calls == 2 and len(budgets.released) == 2
    assert len(budgets.reserved) == reservations_before

    # One failing session must not stop another session using the same tenant.
    other = PlatformModelGatewayTokenAuthority(signing_key=SIGNING_KEY, tenant_id=TENANT_ID)
    other_token = other.issue(session_id=uuid4())
    assert (
        client.post(
            "/v1/responses", headers={"Authorization": f"Bearer {other_token}"}, json=body
        ).status_code
        == 503
    )
    now[0] = 61.0
    assert client.post("/v1/responses", headers=headers, json=body).status_code == 503
    assert calls == 4


def test_provider_retry_after_prevents_early_egress():
    calls = 0
    now = [10.0]

    async def upstream(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"retry-after": "120"})

    client, budgets, token = _client(httpx.MockTransport(upstream), retry_clock=lambda: now[0])
    headers = {"Authorization": f"Bearer {token}"}
    body = {"model": "deepseek-flash", "input": "hello", "stream": True}
    assert client.post("/v1/responses", headers=headers, json=body).status_code == 429
    now[0] = 70.0
    blocked = client.post("/v1/responses", headers=headers, json=body)
    assert blocked.status_code == 424 and blocked.headers["retry-after"] == "60"
    assert calls == 1 and len(budgets.released) == 1
    now[0] = 131.0
    assert client.post("/v1/responses", headers=headers, json=body).status_code == 429
    assert calls == 2


@pytest.mark.parametrize("timeout", [False, True])
def test_transport_failure_is_redacted_and_releases_reservation(timeout, caplog):
    async def upstream(request):
        error = httpx.ReadTimeout if timeout else httpx.ConnectError
        raise error("provider-secret-never-returned", request=request)

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "hello", "stream": True},
    )
    assert response.status_code == (504 if timeout else 502)
    assert response.json()["error"]["retryable"] is True
    assert "provider-secret-never-returned" not in response.text + caplog.text
    assert len(budgets.released) == 1 and not budgets.settled


@pytest.mark.parametrize(
    ("status", "provider_code", "expected_code"),
    [
        (400, "context_length_exceeded", "platform_model_context_length_exceeded"),
        (400, "model_not_found", "platform_model_provider_protocol_unavailable"),
        (429, "insufficient_quota", "platform_model_provider_budget_exhausted"),
    ],
)
def test_allowlisted_provider_error_codes_produce_actionable_diagnostics(
    status, provider_code, expected_code, caplog
):
    client, budgets, token = _client(
        httpx.MockTransport(
            lambda _request: httpx.Response(
                status, json={"error": {"code": provider_code, "message": "private detail"}}
            )
        )
    )
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "hello", "stream": True},
    )
    assert response.json()["error"]["code"] == expected_code
    assert response.json()["error"]["retryable"] is False
    assert f"provider_code={provider_code}" in caplog.text
    assert "private detail" not in caplog.text + response.text
    assert len(budgets.released) == 1 and not budgets.settled


@pytest.mark.parametrize(
    ("value", "seconds"),
    [
        ("Mon, 14 Sep 2026 00:32:00 GMT", "120"),
        ("99999", "3600"),
        ("0", "1"),
        ("-3", "60"),
        ("not-a-date", "60"),
    ],
)
def test_retry_after_is_bounded_and_accepts_http_dates(value, seconds):
    client, _budgets, token = _client(
        httpx.MockTransport(lambda _request: httpx.Response(429, headers={"retry-after": value}))
    )
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "hello", "stream": True},
    )
    assert response.headers["retry-after"] == seconds


def test_oversized_provider_error_is_bounded_closed_and_redacted(caplog):
    class ErrorStream(httpx.AsyncByteStream):
        chunks = 0
        closed = False

        async def __aiter__(self):
            for _ in range(4):
                self.chunks += 1
                yield b"private-provider-detail" * 512

        async def aclose(self):
            self.closed = True

    stream = ErrorStream()
    client, budgets, token = _client(
        httpx.MockTransport(lambda _request: httpx.Response(400, stream=stream))
    )
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "hello", "stream": True},
    )
    assert response.status_code == 400
    assert stream.chunks == 2 and stream.closed
    assert "provider_code=error_body_oversized" in caplog.text
    assert "private-provider-detail" not in response.text + caplog.text
    assert len(budgets.released) == 1


def test_success_clears_previous_transient_failure_without_replaying_requests():
    statuses = iter([503, 200, 503, 503])

    async def upstream(_request):
        return httpx.Response(
            next(statuses),
            content=(
                b'data: {"response":{"usage":{"input_tokens":1,'
                b'"output_tokens":1,"total_tokens":2}}}\n\n'
            ),
        )

    client, budgets, token = _client(httpx.MockTransport(upstream), retry_clock=lambda: 0.0)
    headers = {"Authorization": f"Bearer {token}"}
    body = {"model": "deepseek-flash", "input": "hello", "stream": True}
    for expected in (503, 200, 503, 503, 424):
        assert client.post("/v1/responses", headers=headers, json=body).status_code == expected
    assert len(budgets.released) == 3 and len(budgets.settled) == 1
    assert budgets.settled[0]["actual_tokens"] == 2


def test_interrupted_stream_is_not_replayed_and_keeps_existing_settlement_policy(caplog):
    calls = 0

    class BrokenStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"type":"response.output_text.delta","delta":"hello"}\n\n'
            raise httpx.ReadError("private-stream-error")

    async def upstream(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=BrokenStream())

    client, budgets, token = _client(httpx.MockTransport(upstream), retry_clock=lambda: 0.0)
    headers = {"Authorization": f"Bearer {token}"}
    body = {"model": "deepseek-flash", "input": "hello", "stream": True}
    for _ in range(2):
        with pytest.raises(httpx.ReadError):
            client.post("/v1/responses", headers=headers, json=body)
    assert client.post("/v1/responses", headers=headers, json=body).status_code == 424
    assert calls == 2 and len(budgets.settled) == 2 and not budgets.released
    assert all(s["actual_tokens"] > 0 for s in budgets.settled)
    assert "exception=stream_transport_error" in caplog.text
    assert "private-stream-error" not in caplog.text


def test_failure_tracking_is_bounded_and_scoped_to_configuration_and_tenant():
    from saas.production.platform_model_gateway import _ProviderFailures

    failures = _ProviderFailures(lambda: 0.0)
    key = (TENANT_ID, SESSION_ID, 7)
    failures.failed(key)
    failures.failed(key)
    assert failures.cooldown(key) == 60
    assert failures.cooldown((TENANT_ID, SESSION_ID, 8)) == 0
    assert failures.cooldown((uuid4(), SESSION_ID, 7)) == 0
    for _ in range(4100):
        failures.failed((TENANT_ID, uuid4(), 7))
    assert len(failures._states) == 4096


def test_unreadable_provider_error_still_releases_budget_and_closes_stream(caplog):
    class BrokenErrorStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield b'{"error":'
            raise httpx.ReadError("private-provider-detail")

        async def aclose(self):
            self.closed = True

    stream = BrokenErrorStream()
    client, budgets, token = _client(
        httpx.MockTransport(lambda _request: httpx.Response(400, stream=stream))
    )
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "hello", "stream": True},
    )
    assert response.status_code == 400 and stream.closed
    assert len(budgets.released) == 1 and not budgets.settled
    assert "provider_code=error_body_unavailable" in caplog.text
    assert "private-provider-detail" not in response.text + caplog.text


def test_slow_provider_error_body_has_a_separate_bounded_read_deadline(caplog):
    class SlowErrorStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield b'{"error":'
            await asyncio.sleep(10)
            raise AssertionError("error body read exceeded its deadline")

        async def aclose(self):
            self.closed = True

    stream = SlowErrorStream()
    client, budgets, token = _client(
        httpx.MockTransport(lambda _request: httpx.Response(400, stream=stream))
    )
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "hello", "stream": True},
    )
    assert response.status_code == 400 and stream.closed
    assert len(budgets.released) == 1 and not budgets.settled
    assert "provider_code=error_body_unavailable" in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        b"<html>private-provider-detail</html>",
        b'{"error":"private-provider-detail"}',
        b'{"error":{"code":["private-provider-detail"]}}',
        b"\xff",
        b"[" * 2000 + b'"private-provider-detail"' + b"]" * 2000,
    ],
    ids=["html", "string-error", "invalid-code-type", "invalid-encoding", "deep-json"],
)
def test_malformed_provider_errors_keep_original_classification_and_release_budget(body, caplog):
    client, budgets, token = _client(
        httpx.MockTransport(lambda _request: httpx.Response(400, content=body))
    )
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "hello", "stream": True},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "platform_model_provider_request_invalid"
    assert len(budgets.released) == 1 and not budgets.settled
    assert "private-provider-detail" not in response.text + caplog.text


@pytest.mark.parametrize("provider_status", [401, 503])
def test_existing_relay_preserves_classification_without_auth_refresh_or_task_replay(
    provider_status,
):
    provider_calls = []

    async def upstream(request):
        provider_calls.append(request)
        return httpx.Response(provider_status)

    gateway_client, budgets, _ = _client(httpx.MockTransport(upstream))
    attempts = []

    async def gateway_transport(request):
        attempts.append(request)
        response = await asyncio.to_thread(
            gateway_client.post,
            request.url.path,
            headers={"Authorization": request.headers["authorization"]},
            content=request.content,
        )
        return httpx.Response(
            response.status_code, content=response.content, headers=response.headers
        )

    relay = PlatformModelRelay(
        authority=PlatformModelGatewayTokenAuthority(signing_key=SIGNING_KEY, tenant_id=TENANT_ID),
        session_id=SESSION_ID,
        ttl_seconds=60,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(gateway_transport)),
    )
    expected = [424] if provider_status == 401 else [503, 503, 424]
    with TestClient(relay.app) as client:
        for status in expected:
            response = client.post(
                "/v1/responses",
                headers={"Authorization": f"Bearer {relay.capability}"},
                json={"model": "deepseek-flash", "input": "preserve this task", "stream": True},
            )
            assert response.status_code == status
            assert response.json()["error"]["request_id"] in response.json()["error"]["message"]
    assert len(attempts) == len(expected)
    assert len({request.headers["authorization"] for request in attempts}) == 1
    assert len(provider_calls) == (1 if provider_status == 401 else 2)
    assert len(budgets.released) == len(provider_calls) and not budgets.settled
    if provider_status == 503:
        assert response.json()["error"]["retry_after_seconds"] > 0
        assert "Retry after" in response.json()["error"]["message"]


def test_unconfigured_provider_is_ready_but_requests_fail_closed() -> None:
    calls = 0

    async def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"data: [DONE]\n\n")

    client, budgets, token = _client(httpx.MockTransport(upstream), configuration=None)

    assert client.get("/healthz").status_code == 200
    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "messages": [], "stream": True},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "platform_model_provider_unavailable"
    assert calls == 0
    assert not budgets.reserved


def test_rejects_invalid_token_and_model_before_provider_egress() -> None:
    calls = 0

    async def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"data: [DONE]\n\n")

    client, budgets, token = _client(httpx.MockTransport(upstream))
    invalid = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer invalid"},
        json={"model": "deepseek-flash", "messages": [], "stream": True},
    )
    disallowed = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-not-allowed", "messages": [], "stream": True},
    )

    assert invalid.status_code == 401
    assert disallowed.status_code == 400
    assert calls == 0
    assert not budgets.reserved


def test_configuration_generation_change_releases_reservation() -> None:
    client, budgets, token = _client(
        httpx.MockTransport(lambda _request: httpx.Response(500)),
        configuration=replace(_configuration(), configuration_version=8),
    )
    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "messages": [], "stream": True},
    )

    assert response.status_code == 409
    assert len(budgets.released) == 1


def test_token_is_partition_session_and_expiry_bound() -> None:
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=SIGNING_KEY,
        tenant_id=TENANT_ID,
    )
    token = authority.issue(session_id=SESSION_ID, ttl_seconds=60, now=100)

    claims = authority.validate(token, now=120)
    assert claims.tenant_id == TENANT_ID
    assert claims.session_id == SESSION_ID
    try:
        authority.validate(token, now=161)
    except ValueError:
        pass
    else:  # pragma: no cover - explicit fail-loud branch
        raise AssertionError("expired model gateway token was accepted")


@pytest.mark.parametrize(
    "kind,code",
    [
        ("expired", "platform_model_authentication_expired"),
        ("tampered", "platform_model_authentication_invalid"),
        ("wrong-tenant", "platform_model_authentication_invalid"),
    ],
)
def test_expiry_classification_never_reaches_budget_or_provider(kind, code):
    def upstream(_request):
        raise AssertionError("rejected authentication reached provider")

    client, budgets, _ = _client(httpx.MockTransport(upstream))
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=SIGNING_KEY,
        tenant_id=uuid4() if kind == "wrong-tenant" else TENANT_ID,
    )
    token = authority.issue(session_id=SESSION_ID, ttl_seconds=60, now=1000)
    if kind == "tampered":
        token += "tampered"
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "input": "no side effects"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == code
    assert not budgets.reserved and not budgets.settled and not budgets.released
    assert response.headers["cache-control"] == "no-store"


def test_enabled_tenant_stream_is_attributed_and_foreign_key_cannot_reach_provider(tmp_path):
    tenant = uuid4()
    key = b"independent-synthetic-tenant-key!!"
    key_file = tmp_path / "tenant-key"
    key_file.write_bytes(key)
    key_file.chmod(0o400)
    verifier = TenantModelTokenVerifier(
        PlatformModelGatewayTokenAuthority(signing_key=SIGNING_KEY, tenant_id=TENANT_ID),
        SIGNING_KEY,
        (TenantModelKeyBinding(tenant, 91, f"omnigent-sandbox-model-{tenant.hex}", key_file),),
    )
    provider_requests = []

    def upstream(request):
        provider_requests.append(request)
        return httpx.Response(
            200,
            content=(
                b'data: {"type":"response.completed","response":{'
                b'"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}\n\n'
            ),
        )

    client, budgets, _ = _client(httpx.MockTransport(upstream), tokens=verifier)
    valid = PlatformModelGatewayTokenAuthority(signing_key=key, tenant_id=tenant).issue(
        session_id=SESSION_ID,
    )
    response = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {valid}"},
        json={"model": "deepseek-flash", "input": "synthetic tenant stream", "stream": True},
    )
    assert response.status_code == 200 and "response.completed" in response.text
    assert budgets.reserved[0]["tenant_id"] == tenant
    assert budgets.reserved[0]["run_id"] == SESSION_ID
    assert budgets.settled and len(provider_requests) == 1
    reservation_count = len(budgets.reserved)
    forged = PlatformModelGatewayTokenAuthority(signing_key=SIGNING_KEY, tenant_id=tenant).issue(
        session_id=SESSION_ID,
    )
    rejected = client.post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {forged}"},
        json={"model": "deepseek-flash", "input": "must not run", "stream": True},
    )
    assert rejected.status_code == 401
    assert len(provider_requests) == 1 and len(budgets.reserved) == reservation_count


def test_relay_expiry_recovery_with_real_gateway_settles_one_model_call(monkeypatch):
    provider_requests = []

    async def upstream(request):
        provider_requests.append(request)
        return httpx.Response(
            200,
            stream=httpx.ByteStream(
                b'data: {"type":"response.completed","response":{'
                b'"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}\n\n'
            ),
        )

    gateway_client, budgets, _ = _client(httpx.MockTransport(upstream))
    real_validate = PlatformModelGatewayTokenAuthority.validate
    monkeypatch.setattr(
        PlatformModelGatewayTokenAuthority,
        "validate",
        lambda self, token, **kwargs: real_validate(self, token, now=1060),
    )
    host_clock = [1000]
    attempts = []

    async def gateway_transport(request):
        attempts.append(request)
        response = await asyncio.to_thread(
            gateway_client.post,
            request.url.path,
            headers={"Authorization": request.headers["authorization"]},
            content=request.content,
        )
        host_clock[0] = 1001
        return httpx.Response(response.status_code, stream=httpx.ByteStream(response.content))

    relay = PlatformModelRelay(
        authority=PlatformModelGatewayTokenAuthority(signing_key=SIGNING_KEY, tenant_id=TENANT_ID),
        session_id=SESSION_ID,
        ttl_seconds=60,
        clock=lambda: host_clock[0],
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(gateway_transport)),
    )
    with TestClient(relay.app) as client:
        response = client.post(
            "/v1/responses",
            headers={"Authorization": f"Bearer {relay.capability}"},
            json={
                "model": "deepseek-flash",
                "input": "one model call",
                "max_output_tokens": 100,
                "stream": True,
            },
        )
    assert response.status_code == 200
    assert len(attempts) == 2
    assert len(provider_requests) == 1
    assert len(budgets.settled) == 1
    assert budgets.settled[0]["actual_tokens"] == 15
    assert not budgets.released
    assert attempts[0].content == attempts[1].content


@pytest.mark.parametrize("failure", [None, "spawn", "follow"])
def test_managed_host_injects_runner_only_session_channel(
    monkeypatch,
    tmp_path: Path,
    failure,
) -> None:
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=SIGNING_KEY,
        tenant_id=TENANT_ID,
    )
    captured: dict[str, str] = {}

    class Relay:
        capability = "runner-only-capability-not-a-gateway-token"

        def __init__(self, **kwargs):
            assert kwargs["authority"] is authority
            assert kwargs["session_id"] == SESSION_ID

        def start(self):
            return "http://127.0.0.1:12345/v1"

        def follow(self, _process):
            captured["followed"] = "yes"
            if failure == "follow":
                raise OSError("monitor unavailable")

        def close(self):
            captured["closed"] = "yes"

    monkeypatch.setattr("saas.production.platform_model_host.PlatformModelRelay", Relay)

    def fake_spawn(
        _self: HostProcess,
        environment: dict[str, str],
        _session_slug: str,
        _workspace: Path,
    ):
        captured["token"] = environment[PLATFORM_MODEL_CREDENTIAL_ENV]
        captured["transport"] = environment[PLATFORM_MODEL_RELAY_BASE_URL_ENV]
        if failure == "spawn":
            raise OSError("spawn failed")
        return cast(object, object()), tmp_path / "runner.log"

    monkeypatch.setattr(HostProcess, "_spawn_runner_proc", fake_spawn)
    monkeypatch.setattr(
        HostProcess,
        "_stop_runner_proc",
        staticmethod(lambda _proc: captured.update(stopped="yes")),
    )
    host = PlatformModelHostProcess(
        HostIdentity(host_id="0123456789abcdef0123456789abcdef", name="model-host"),
        "https://control-plane.invalid",
        token_authority=authority,
        token_ttl_seconds=3600,
    )
    environment = {PRIMARY_SESSION_ID_ENV_VAR: str(SESSION_ID)}

    if failure is None:
        host._spawn_runner_proc(environment, "session-", tmp_path)
    else:
        with pytest.raises(OSError):
            host._spawn_runner_proc(environment, "session-", tmp_path)

    assert PLATFORM_MODEL_CREDENTIAL_ENV not in environment
    assert PLATFORM_MODEL_RELAY_BASE_URL_ENV not in environment
    assert captured["token"] == Relay.capability
    assert json.loads(captured["transport"]) == {
        "platform-deepseek": {"openai": "http://127.0.0.1:12345/v1"}
    }
    assert ("followed" in captured) == (failure != "spawn")
    assert ("closed" in captured) == (failure is not None)
    assert ("stopped" in captured) == (failure == "follow")


def test_pricing_policy_requires_canonical_read_only_file(tmp_path: Path) -> None:
    path = tmp_path / "pricing.json"
    document = {
        "catalog_sha256": "fc2923d2ab3ac92a2b1b16fef40cbcfbb139c3abcd9f4e7d3b3e3c34a8e8427c",
        "rates": [
            {
                "model_sha256": "7d963f65d1ede1bd9416a5f55575efe0d202e0a00519ef04e47dae20c3180445",
                "off_peak_input_cache_hit_microusd_per_million_tokens": 3_000,
                "off_peak_input_cache_miss_microusd_per_million_tokens": 150_000,
                "off_peak_output_microusd_per_million_tokens": 600_000,
                "peak_input_cache_hit_microusd_per_million_tokens": 6_000,
                "peak_input_cache_miss_microusd_per_million_tokens": 300_000,
                "peak_output_microusd_per_million_tokens": 1_200_000,
            }
        ],
        "revision": "pricing-20260914",
        "schema_version": 2,
    }
    path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    path.chmod(0o444)

    policy = load_platform_model_pricing({"OMNIGENT_SAAS_PLATFORM_MODEL_PRICING_FILE": str(path)})

    assert policy.revision == "pricing-20260914"
    assert (
        policy.for_catalog(("deepseek-flash",))[
            "deepseek-flash"
        ].peak_output_microusd_per_million_tokens
        == 1_200_000
    )

    path.chmod(0o644)
    path.write_text(json.dumps(document, indent=2), encoding="ascii")
    path.chmod(0o444)
    try:
        load_platform_model_pricing({"OMNIGENT_SAAS_PLATFORM_MODEL_PRICING_FILE": str(path)})
    except ValueError:
        pass
    else:  # pragma: no cover - explicit fail-loud branch
        raise AssertionError("non-canonical pricing policy was accepted")


def test_packaged_pricing_tracks_current_deepseek_catalog_and_peak_windows() -> None:
    root = Path(__file__).resolve().parents[2]
    policy = load_platform_model_pricing(
        {
            "OMNIGENT_SAAS_PLATFORM_MODEL_PRICING_FILE": str(
                root / "saas/production/deepseek_pricing.json"
            )
        }
    )

    assert policy.revision == "pricing-20260915-v4.2"
    prices = policy.for_catalog(("deepseek-flash", "deepseek-v4-pro"))
    assert set(prices) == {"deepseek-flash", "deepseek-v4-pro"}
    assert set(policy.for_catalog(("deepseek-v4-pro",))) == {"deepseek-v4-pro"}
    flash = prices["deepseek-flash"]
    assert flash.rates_at(datetime(2026, 9, 14, 1, 0, tzinfo=timezone.utc)) == (
        6_000,
        300_000,
        1_200_000,
    )
    assert flash.rates_at(datetime(2026, 9, 14, 4, 0, tzinfo=timezone.utc)) == (
        3_000,
        150_000,
        600_000,
    )
    assert flash.rates_at(datetime(2026, 9, 13, 7, 0, tzinfo=timezone.utc)) == (
        3_000,
        150_000,
        600_000,
    )


def test_host_gateway_config_contains_only_synthetic_bearer_name() -> None:
    rendered = render_platform_model_gateway_config(
        allowed_models=("deepseek-flash", "deepseek-v4-pro"),
        default_model="deepseek-flash",
    )
    document = json.loads(rendered)
    provider = document["providers"]["platform-deepseek"]["openai"]

    assert document["providers"]["platform-deepseek"]["default"] == ["openai", "pi"]
    assert provider["base_url"] == "http://omnigent-platform-model-gateway:8090/v1"
    assert provider["api_key"] == PLATFORM_MODEL_CREDENTIAL_REFERENCE
    assert provider["wire_api"] == "responses"
    assert provider["context_window"] == 1_000_000
    assert provider["max_output_tokens"] == 65_536
    assert "sk-" not in rendered


def test_gateway_composition_requires_isolated_billing_and_secret_bindings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from saas.production import platform_model_gateway as module

    key = tmp_path / "gateway-token-key"
    key.write_bytes(SIGNING_KEY)
    key.chmod(0o400)
    pricing = PlatformModelPricingPolicy(
        revision="pricing-test-20260914",
        catalog_sha256="fc2923d2ab3ac92a2b1b16fef40cbcfbb139c3abcd9f4e7d3b3e3c34a8e8427c",
        prices=(
            PlatformModelPrice(
                model_sha256="7d963f65d1ede1bd9416a5f55575efe0d202e0a00519ef04e47dae20c3180445",
                peak_input_cache_hit_microusd_per_million_tokens=6_000,
                peak_input_cache_miss_microusd_per_million_tokens=300_000,
                peak_output_microusd_per_million_tokens=1_200_000,
                off_peak_input_cache_hit_microusd_per_million_tokens=3_000,
                off_peak_input_cache_miss_microusd_per_million_tokens=150_000,
                off_peak_output_microusd_per_million_tokens=600_000,
            ),
        ),
    )
    bindings = ProductionServiceRoleBindings(
        path=tmp_path / "platform-model-bindings.json",
        sha256="0" * 64,
        bindings=(
            ProductionServiceRoleBinding("billing", "next_beta_billing", "saas_billing"),
            ProductionServiceRoleBinding(
                "secret_broker", "next_beta_secret_broker", "saas_secret_broker"
            ),
        ),
    )
    engines: list[sa.Engine] = []
    real_create_engine = sa.create_engine

    def engine(_url: str, **_kwargs) -> sa.Engine:
        created = real_create_engine("sqlite+pysqlite://")
        engines.append(created)
        return created

    monkeypatch.setattr(module, "load_platform_model_service_role_bindings", lambda _env: bindings)
    monkeypatch.setattr(
        module,
        "load_production_database_url_file",
        lambda _env, role: (
            f"postgresql+psycopg://next_beta_{role}:redacted@example.test/omnigent",
            make_url(f"postgresql+psycopg://next_beta_{role}:redacted@example.test/omnigent"),
            tmp_path / role,
        ),
    )
    monkeypatch.setattr(module.sa, "create_engine", engine)
    monkeypatch.setattr(module, "_inspect_service_login", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "build_production_secret_cipher", lambda _env: object())
    monkeypatch.setattr(module, "load_platform_model_pricing", lambda _env: pricing)
    monkeypatch.setattr(
        module,
        "ModelProviderConfigurationReader",
        lambda *_args, **_kwargs: _ConfigurationReader(None),
    )

    app, built_engines = build_platform_model_gateway(
        {
            "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID": str(TENANT_ID),
            "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE": str(key),
        }
    )

    assert app is not None
    assert built_engines == tuple(engines)
    health = TestClient(app).get("/healthz")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "provider_secret_exported": False}
    for built in built_engines:
        built.dispose()


def test_module_entrypoint_runs_after_response_helpers() -> None:
    from saas.production import platform_model_gateway as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_error_response"
    )
    entrypoint = next(
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
    )

    assert entrypoint.lineno > (helper.end_lineno or helper.lineno)


@pytest.mark.parametrize("endpoint", ["chat/completions", "responses"])
@pytest.mark.parametrize(
    "component,usage_state",
    [
        ("gateway", "absent"),
        ("gateway", "interim"),
        ("gateway", "terminal"),
        ("gateway", "malformed"),
        ("relay", "absent"),
    ],
)
def test_client_disconnect_cannot_cancel_stream_finalization(
    endpoint: str, component: str, usage_state: str
) -> None:
    import anyio
    from fastapi import FastAPI
    from starlette.types import ASGIApp, Message, Scope

    class ProviderStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            total = 14 if usage_state == "malformed" else 15
            if endpoint == "responses":
                frame = b'data: {"type":"response.output_text.delta","delta":"hello"}\n\n'
                if usage_state != "absent":
                    event = {
                        "type": "response.in_progress"
                        if usage_state == "interim"
                        else "response.completed",
                        "response": {
                            "usage": {
                                "input_tokens": 10,
                                "input_tokens_details": {"cached_tokens": 4},
                                "output_tokens": 5,
                                "total_tokens": total,
                            }
                        },
                    }
                    frame += b"data: " + json.dumps(event).encode() + b"\n\n"
            else:
                frame = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
                if usage_state != "absent":
                    event = {
                        "choices": [],
                        "usage": {
                            "prompt_tokens": 10,
                            "prompt_cache_hit_tokens": 4,
                            "prompt_cache_miss_tokens": 6,
                            "completion_tokens": 5,
                            "total_tokens": total,
                        },
                    }
                    frame += b"data: " + json.dumps(event).encode() + b"\n\n"
                    if usage_state != "interim":
                        frame += b"data: [DONE]\n\n"
            yield frame
            await anyio.sleep_forever()

        async def aclose(self) -> None:
            await anyio.sleep(0)
            self.closed = True

    provider = ProviderStream()
    requests: list[httpx.Request] = []

    async def upstream(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, stream=provider)

    client, budgets, token = _client(httpx.MockTransport(upstream))
    application = cast(FastAPI, client.app)
    if component == "relay":
        relay = PlatformModelRelay(
            authority=PlatformModelGatewayTokenAuthority(
                signing_key=SIGNING_KEY, tenant_id=TENANT_ID
            ),
            session_id=SESSION_ID,
            ttl_seconds=60,
            clock=lambda: 1000,
            client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
        )
        application = relay.app
        token = relay.capability
    payload: dict[str, object] = {"model": "deepseek-flash", "stream": True}
    if endpoint == "responses":
        payload.update(input="hello", max_output_tokens=100)
    else:
        payload.update(messages=[{"role": "user", "content": "hello"}], max_tokens=100)

    async def disconnect_after_output() -> None:
        output = anyio.Event()
        body_sent = False

        async def receive() -> Message:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": json.dumps(payload).encode()}
            await output.wait()
            return {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            if message["type"] == "http.response.body" and message.get("body"):
                output.set()

        scope: Scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/v1/" + endpoint,
            "raw_path": ("/v1/" + endpoint).encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [
                (b"content-type", b"application/json"),
                (b"authorization", ("Bearer " + token).encode()),
            ],
            "client": ("127.0.0.1", 12345),
            "server": ("gateway.test", 443),
        }
        with anyio.fail_after(3):
            async with application.router.lifespan_context(application):
                await cast(ASGIApp, application)(scope, receive, send)

    anyio.run(disconnect_after_output)

    assert len(requests) == 1
    if component == "gateway":
        assert (provider.closed, len(budgets.settled)) == (True, 1)
        if usage_state == "terminal":
            assert budgets.settled[0]["actual_tokens"] == 15
            assert budgets.settled[0]["actual_microusd"] == 5
        else:
            assert budgets.settled[0]["actual_tokens"] == budgets.reserved[0]["requested_tokens"]
            assert (
                budgets.settled[0]["actual_microusd"] == budgets.reserved[0]["requested_microusd"]
            )
    else:
        assert provider.closed
        assert not budgets.reserved and not budgets.settled
    assert not budgets.released
