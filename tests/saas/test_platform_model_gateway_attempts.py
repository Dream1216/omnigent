from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import httpx
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.model_pricing import PlatformModelPrice, PlatformModelPricingPolicy
from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
    ModelProviderMonthlyBudgetRecord,
)
from saas.production.platform_model_gateway import (
    PlatformModelGateway,
    create_platform_model_gateway_app,
)
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority
from tests.saas.test_model_provider_budget import _service
from tests.saas.test_platform_model_gateway import (
    SESSION_ID,
    SIGNING_KEY,
    TENANT_ID,
    _configuration,
    _ConfigurationReader,
)


def _fixture(tmp_path, handler, *, responses=False, client_factory=None, budget_database=None):
    budgets, sessions = _service(tmp_path) if budget_database is None else budget_database
    with sessions.begin() as db:
        row = db.get(ModelProviderConfigurationRecord, "deepseek")
        row.version, row.monthly_budget_microusd, row.per_tenant_daily_token_limit = (
            7,
            100_000_000,
            100_000_000,
        )
    model = "deepseek-flash"
    prices = PlatformModelPricingPolicy(
        "gateway-attempt-v1",
        sha256(json.dumps([model], separators=(",", ":")).encode()).hexdigest(),
        (PlatformModelPrice(sha256(model.encode()).hexdigest(), *(1_000_000,) * 6),),
    )
    tokens = PlatformModelGatewayTokenAuthority(signing_key=SIGNING_KEY, tenant_id=TENANT_ID)
    gateway = PlatformModelGateway(
        tokens=tokens,
        configurations=_ConfigurationReader(_configuration()),
        budgets=budgets,
        pricing=prices,
        client_factory=client_factory
        or (lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    app = create_platform_model_gateway_app(gateway)
    client = TestClient(app, raise_server_exceptions=False)
    path = "/v1/responses" if responses else "/v1/chat/completions"
    request = {
        "headers": {"Authorization": "Bearer " + tokens.issue(session_id=SESSION_ID)},
        "json": {
            "model": model,
            "stream": True,
            "max_output_tokens" if responses else "max_tokens": 32,
            "input" if responses else "messages": "hello" if responses else [],
        },
    }
    return client, path, request, budgets, sessions, app


def _row(sessions):
    with sessions() as db:
        return db.scalar(sa.select(ModelProviderBudgetReservationRecord))


def _body(*, responses=False, terminal=True):
    if responses:
        return (
            b'data: {"type":"response.completed","response":{"usage":'
            b'{"input_tokens":10,"output_tokens":3,"total_tokens":13}}}\n\n'
            if terminal
            else b'data: {"type":"response.in_progress","response":{"usage":'
            b'{"input_tokens":10,"output_tokens":3,"total_tokens":13}}}\n\n'
        )
    return (
        b'data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":3,'
        b'"total_tokens":13}}\n\n' + (b"data: [DONE]\n\n" if terminal else b"")
    )


@pytest.mark.parametrize("responses", (False, True))
def test_real_budget_is_fenced_before_egress_and_resolves_bound_usage(tmp_path, responses):
    def handler(_request):
        assert _row(sessions).status == "in_flight"
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=_body(responses=responses)
        )

    client, path, request, _, sessions, _ = _fixture(tmp_path, handler, responses=responses)
    response = client.post(path, **request)
    assert response.status_code == 200
    row = _row(sessions)
    assert row.status == "settled" and row.settled_tokens == 13 and row.settled_microusd == 13
    assert row.outcome_evidence_sha256 is not None and len(row.outcome_evidence_sha256) == 64


@pytest.mark.parametrize(
    "case",
    (
        "missing_usage",
        "missing_terminal",
        "bad_last_usage",
        "read_error",
        "401",
        "write_error",
        "empty",
    ),
)
def test_ambiguous_sent_requests_keep_the_hold_without_fabricating_actual_spend(tmp_path, case):
    calls = []

    class BrokenStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
            raise httpx.ReadError("isolated partial response")

    def handler(request):
        calls.append(request.url.path)
        if case == "write_error":
            raise httpx.WriteError("isolated ambiguous write")
        if case == "401":
            return httpx.Response(401, json={"error": "private-supplier-error"})
        if case == "read_error":
            return httpx.Response(
                200, stream=BrokenStream(), headers={"content-type": "text/event-stream"}
            )
        content = {
            "missing_usage": (
                b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\ndata: [DONE]\n\n'
            ),
            "missing_terminal": _body(terminal=False),
            "bad_last_usage": _body(terminal=False)
            + b'data: {"usage":{"total_tokens":false}}\n\ndata: [DONE]\n\n',
            "empty": b"",
        }[case]
        return httpx.Response(200, content=content, headers={"content-type": "text/event-stream"})

    client, path, request, budgets, sessions, _ = _fixture(tmp_path, handler)
    response = client.post(path, **request)
    assert response.status_code in {200, 502}
    assert "private-supplier-error" not in response.text
    row = _row(sessions)
    assert row.status == "uncertain"
    assert (
        row.settled_microusd
        == row.settled_tokens
        == row.released_microusd
        == row.released_tokens
        == 0
    )
    assert budgets.recover_expired(now=datetime.now(timezone.utc) + timedelta(days=1)) == ()
    with sessions() as db:
        counter = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord))
        assert counter.reserved_microusd == row.admitted_microusd and counter.settled_microusd == 0
    assert len(calls) == 1


def test_response_progress_usage_is_not_a_terminal_cost_receipt(tmp_path):
    def handler(_request):
        return httpx.Response(
            200,
            content=_body(responses=True, terminal=False),
            headers={"content-type": "text/event-stream"},
        )

    client, path, request, _, sessions, _ = _fixture(tmp_path, handler, responses=True)
    assert client.post(path, **request).status_code == 200
    assert _row(sessions).status == "uncertain"


@pytest.mark.parametrize(
    "delta",
    ({}, {"content": ""}, {"role": "assistant", "content": None, "tool_calls": None}),
)
def test_litellm_usage_only_choice_retains_no_extra_output_and_resolves_cost(tmp_path, delta):
    def handler(_request):
        usage = json.loads(_body(terminal=False).splitlines()[0][5:])
        usage["choices"] = [{"index": 0, "delta": delta, "finish_reason": None}]
        body = b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
        body += b"data: " + json.dumps(usage).encode() + b"\n\ndata: [DONE]\n\n"
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    client, path, request, _, sessions, _ = _fixture(tmp_path, handler)
    assert client.post(path, **request).status_code == 200
    row = _row(sessions)
    assert row.status == "settled" and row.settled_tokens == row.settled_microusd == 13


@pytest.mark.parametrize(
    "choices",
    (
        [{"index": 0, "delta": {"content": "more output"}}],
        [{"index": 0, "delta": {"tool_calls": [{"function": {"arguments": "{}"}}]}}],
        [{"index": 0, "delta": {"role": "user"}}],
        [{"index": 1, "delta": {}}],
        [{"index": True, "delta": {}}],
        [{"index": 0, "delta": "invalid"}],
        [{"index": 0, "delta": {}, "message": {"content": "non-streaming output"}}],
        [{"index": 0, "delta": {}}, {"index": 1, "delta": {}}],
        {"index": 0, "delta": {}},
    ),
)
def test_usage_bearing_choice_with_output_or_invalid_shape_remains_uncertain(tmp_path, choices):
    def handler(_request):
        usage = json.loads(_body(terminal=False).splitlines()[0][5:])
        usage["choices"] = choices
        return httpx.Response(
            200,
            content=b"data: " + json.dumps(usage).encode() + b"\n\ndata: [DONE]\n\n",
            headers={"content-type": "text/event-stream"},
        )

    client, path, request, _, sessions, _ = _fixture(tmp_path, handler)
    assert client.post(path, **request).status_code == 200
    row = _row(sessions)
    assert row.status == "uncertain" and row.settled_tokens == row.settled_microusd == 0


@pytest.mark.parametrize("responses", (False, True))
def test_explicit_terminal_zero_usage_releases_only_with_bound_evidence(tmp_path, responses):
    def handler(_request):
        return httpx.Response(
            200,
            content=_body(responses=responses)
            .replace(b":10", b":0")
            .replace(b":3", b":0")
            .replace(b":13", b":0"),
            headers={"content-type": "text/event-stream"},
        )

    client, path, request, _, sessions, _ = _fixture(tmp_path, handler, responses=responses)
    assert client.post(path, **request).status_code == 200
    row = _row(sessions)
    assert row.status == "released" and row.settled_tokens == row.settled_microusd == 0
    assert row.released_microusd == row.admitted_microusd
    assert row.released_tokens == row.admitted_tokens
    assert row.outcome_evidence_sha256 is not None


@pytest.mark.parametrize(
    "case", ("invalid_json", "oversize", "after_terminal", "after_usage", "excess_usage")
)
def test_invalid_receipt_never_falls_back_to_an_earlier_usage_frame(tmp_path, case):
    content = {
        "invalid_json": _body(terminal=False) + b"data: not-json\n\ndata: [DONE]\n\n",
        "oversize": _body() + b"data: " + b"x" * (256 * 1024 + 1),
        "after_terminal": _body() + _body(),
        "after_usage": _body(terminal=False)
        + b'data: {"choices":[{"delta":{"content":"more output"}}]}\n\ndata: [DONE]\n\n',
        "excess_usage": _body().replace(b":10", b":1000000").replace(b":13", b":1000003"),
    }[case]

    def handler(_request):
        return httpx.Response(200, content=content, headers={"content-type": "text/event-stream"})

    client, path, request, _, sessions, _ = _fixture(tmp_path, handler)
    assert client.post(path, **request).status_code == 200
    row = _row(sessions)
    assert row.status == "uncertain" and row.settled_tokens == row.settled_microusd == 0


@pytest.mark.parametrize("phase", ("transport", "fence", "fence_ack_lost"))
def test_setup_failure_never_sends_inference_or_releases_a_committed_fence(
    tmp_path, monkeypatch, phase
):
    calls = []

    def handler(request):
        calls.append(request)
        raise AssertionError("Setup failure must precede egress")

    def fail_transport():
        raise OSError("local setup")

    client, path, request, budgets, sessions, _ = _fixture(
        tmp_path,
        handler,
        client_factory=fail_transport if phase == "transport" else None,
    )
    original = budgets.begin_attempt

    def fail(**kwargs):
        if phase == "fence_ack_lost":
            original(**kwargs)
        raise OSError("isolated database acknowledgement loss")

    if phase != "transport":
        monkeypatch.setattr(budgets, "begin_attempt", fail)
    assert client.post(path, **request).status_code == 503
    row = _row(sessions)
    assert not calls and row.settled_tokens == row.settled_microusd == 0
    assert row.status == ("in_flight" if phase == "fence_ack_lost" else "released")
    assert budgets.recover_expired(now=datetime.now(timezone.utc) + timedelta(days=1)) == ()


@pytest.mark.parametrize("committed", (False, True))
def test_settlement_failure_keeps_a_hold_or_recovers_one_committed_result(
    tmp_path, monkeypatch, committed
):
    calls, outcomes = [], []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, content=_body(), headers={"content-type": "text/event-stream"})

    client, path, request, budgets, sessions, _ = _fixture(tmp_path, handler)
    original = budgets.resolve_attempt

    def lose_acknowledgement(**kwargs):
        outcomes.append(kwargs)
        if committed:
            original(**kwargs)
        raise OSError("isolated settlement acknowledgement loss")

    monkeypatch.setattr(budgets, "resolve_attempt", lose_acknowledgement)
    assert client.post(path, **request).status_code == 200
    row = _row(sessions)
    assert row.status == ("settled" if committed else "uncertain")
    assert row.settled_microusd == (13 if committed else 0)
    assert original(**outcomes[0]).replayed is committed
    assert original(**outcomes[0]).replayed
    with sessions() as db:
        counter = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord))
        assert counter.settled_microusd == 13 and counter.reserved_microusd == 0
    assert len(calls) == len(outcomes) == 1


@pytest.mark.parametrize("responses", (False, True))
@pytest.mark.parametrize("failure", ("after_receipt", "cleanup", "oversize_fragmented"))
def test_transport_failure_cannot_replace_the_observed_financial_outcome(
    tmp_path, responses, failure
):
    class BrokenTransport(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield _body(responses=responses)
            if failure == "after_receipt":
                raise httpx.ReadError("isolated failure after terminal usage")
            if failure == "oversize_fragmented":
                yield b"data: " + b"x" * (256 * 1024 + 1)

        async def aclose(self):
            if failure == "cleanup":
                raise OSError("isolated cleanup failure")

    def handler(_request):
        return httpx.Response(
            200, stream=BrokenTransport(), headers={"content-type": "text/event-stream"}
        )

    client, path, request, _, sessions, _ = _fixture(tmp_path, handler, responses=responses)
    assert client.post(path, **request).status_code == 200
    row = _row(sessions)
    known = failure != "oversize_fragmented"
    assert row.status == ("settled" if known else "uncertain")
    assert row.settled_microusd == row.settled_tokens == (13 if known else 0)


@pytest.mark.anyio
async def test_client_cancel_after_output_preserves_the_sent_attempt(tmp_path):
    emitted = asyncio.Event()

    class WaitingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
            emitted.set()
            await asyncio.Future()

    def handler(_request):
        return httpx.Response(
            200, stream=WaitingStream(), headers={"content-type": "text/event-stream"}
        )

    _, path, request, _, sessions, app = _fixture(tmp_path, handler)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://isolated.test"
    ) as client:
        pending = asyncio.create_task(client.post(path, **request))
        await asyncio.wait_for(emitted.wait(), timeout=5)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
    assert _row(sessions).status == "uncertain"
