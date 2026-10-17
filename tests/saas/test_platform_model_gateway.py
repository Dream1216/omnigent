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
    PlatformModelGateway,
    PlatformModelPrice,
    PlatformModelPricingPolicy,
    _UsageParser,
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
        self.uncertain: list[dict[str, object]] = []
        self.reservations: dict[UUID, ModelProviderBudgetReservationView] = {}

    def reserve(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        self.reserved.append(kwargs)
        requested_microusd = kwargs["requested_microusd"]
        requested_tokens = kwargs["requested_tokens"]
        assert isinstance(requested_microusd, int)
        assert isinstance(requested_tokens, int)
        view = ModelProviderBudgetReservationView(
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
        self.reservations[view.id] = view
        return view

    def _replace(self, kwargs, **changes):
        identity = kwargs["reservation_id"]
        view = replace(self.reservations[identity], **changes)
        self.reservations[identity] = view
        return view

    def begin_attempt(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        assert self.reservations[kwargs["reservation_id"]].status == "reserved"
        return self._replace(kwargs, status="in_flight")

    def mark_uncertain(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        assert self.reservations[kwargs["reservation_id"]].status == "in_flight"
        self.uncertain.append(kwargs)
        return self._replace(kwargs, status="uncertain")

    def resolve_attempt(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        assert self.reservations[kwargs["reservation_id"]].status == "in_flight"
        witness = kwargs["evidence_sha256"]
        if kwargs.get("gateway_usage") is not None:
            assert witness is None
            witness = "f" * 64
        assert isinstance(witness, str) and len(witness) == 64
        self.settled.append(
            {
                name: value
                for name, value in kwargs.items()
                if name not in {"evidence_sha256", "gateway_usage"}
            }
        )
        return self._replace(
            kwargs,
            status="settled",
            settled_microusd=kwargs["actual_microusd"],
            settled_tokens=kwargs["actual_tokens"],
            outcome_evidence_sha256=witness,
        )

    def release(self, **kwargs: object) -> ModelProviderBudgetReservationView:
        assert self.reservations[kwargs["reservation_id"]].status == "reserved"
        self.released.append(kwargs)
        return self._replace(kwargs, status="released")


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
    configuration: PlatformManagedModelRuntimeConfiguration
    | object
    | None = _DEFAULT_CONFIGURATION,
) -> tuple[TestClient, _Budgets, str]:
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=SIGNING_KEY,
        tenant_id=TENANT_ID,
    )
    budgets = _Budgets()
    gateway = PlatformModelGateway(
        tokens=authority,
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
    )
    return (
        TestClient(create_platform_model_gateway_app(gateway)),
        budgets,
        authority.issue(session_id=SESSION_ID, now=int(datetime.now(timezone.utc).timestamp())),
    )


@pytest.mark.parametrize(
    "cache_fields",
    (
        b'"prompt_cache_hit_tokens":4,"prompt_cache_miss_tokens":6,',
        b'"prompt_tokens_details":{"cached_tokens":4},',
    ),
    ids=("deepseek-native-cache", "litellm-standard-cache"),
)
def test_streams_provider_bytes_and_settles_observed_usage(cache_fields: bytes) -> None:
    async def upstream(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer provider-secret-never-returned"
        sent = __import__("json").loads(request.content)
        assert sent["stream_options"] == {"include_usage": True}
        body = (
            b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":10,'
            + cache_fields
            + b'"completion_tokens":5,"total_tokens":15}}\n\n'
            + b"data: [DONE]\n\n"
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


@pytest.mark.parametrize("cached", (-1, 11, True, "4", None))
def test_standard_cache_usage_rejects_invalid_token_counts(cached: object) -> None:
    parser = _UsageParser()
    usage = {
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "total_tokens": 15,
        "prompt_tokens_details": {"cached_tokens": cached},
    }
    parser.feed(("data: " + json.dumps({"usage": usage}) + "\n\n").encode())
    parser.finish()
    assert parser.total_tokens is None


@pytest.mark.parametrize("legacy_hit", (3, True))
def test_standard_cache_usage_does_not_hide_inconsistent_native_fields(
    legacy_hit: object,
) -> None:
    parser = _UsageParser()
    usage = {
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "total_tokens": 15,
        "prompt_cache_hit_tokens": legacy_hit,
        "prompt_cache_miss_tokens": 6,
        "prompt_tokens_details": {"cached_tokens": 4},
    }
    parser.feed(("data: " + json.dumps({"usage": usage}) + "\n\n").encode())
    parser.finish()
    assert parser.total_tokens is None


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


def test_responses_materializes_nullable_output_limit_before_egress() -> None:
    async def upstream(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        assert sent["max_output_tokens"] == 4096
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
    ("responses", "limits", "expected"),
    (
        (False, {}, 4096),
        (False, {"max_tokens": None}, 4096),
        (False, {"max_completion_tokens": None}, 4096),
        (False, {"max_tokens": 17}, 17),
        (False, {"max_completion_tokens": 19}, 19),
        (False, {"max_tokens": 17, "max_completion_tokens": 17}, 17),
        (True, {}, 4096),
        (True, {"max_output_tokens": None}, 4096),
        (True, {"max_output_tokens": 23}, 23),
    ),
)
def test_output_hold_limit_is_always_an_explicit_upstream_bound(
    responses: bool, limits: dict[str, object], expected: int
) -> None:
    async def upstream(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        assert sent["max_output_tokens" if responses else "max_tokens"] == expected
        assert "max_completion_tokens" not in sent
        if responses:
            body = (
                b'data: {"type":"response.completed","response":{"usage":'
                b'{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n'
            )
        else:
            body = (
                b'data: {"usage":{"prompt_tokens":1,"completion_tokens":1,'
                b'"total_tokens":2}}\n\ndata: [DONE]\n\n'
            )
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    client, budgets, token = _client(httpx.MockTransport(upstream))
    document = {"model": "deepseek-flash", "stream": True, **limits}
    document["input" if responses else "messages"] = "hello" if responses else []
    response = client.post(
        "/v1/responses" if responses else "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json=document,
    )
    assert response.status_code == 200
    assert budgets.reserved[0]["requested_tokens"] >= expected
    assert len(budgets.settled) == 1 and not budgets.released


@pytest.mark.parametrize(
    ("responses", "limits"),
    (
        (False, {"max_tokens": 17, "max_completion_tokens": 19}),
        (False, {"max_tokens": None, "max_completion_tokens": 19}),
        (False, {"n": 2}),
        (False, {"n": True}),
        (False, {"n": None}),
        (False, {"n": "1"}),
        (True, {"n": 1}),
    ),
)
def test_ambiguous_or_multisample_limits_fail_before_budget_or_provider(
    responses: bool, limits: dict[str, object]
) -> None:
    calls = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500)

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/responses" if responses else "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "stream": True, **limits},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "platform_model_request_invalid"
    assert not calls and not budgets.reserved and not budgets.settled and not budgets.released


def test_provider_rejection_retains_uncertain_budget_without_leaking_body() -> None:
    async def upstream(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "contains-sensitive-provider-detail"})

    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "deepseek-flash", "messages": [], "stream": True},
    )

    assert response.status_code == 502
    assert "contains-sensitive-provider-detail" not in response.text
    assert len(budgets.uncertain) == 1
    assert not budgets.settled and not budgets.released


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


@pytest.mark.parametrize("managed", [False, True])
def test_gateway_composition_requires_isolated_billing_and_secret_bindings(
    tmp_path: Path,
    monkeypatch,
    managed,
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
            ProductionServiceRoleBinding("app", "next_beta_app", "saas_app"),
            ProductionServiceRoleBinding(
                "authenticator", "next_beta_authenticator", "saas_authenticator"
            ),
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

    source = {
        "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID": str(TENANT_ID),
        "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE": str(key),
    }
    if managed:
        inference_key = tmp_path / "inference-only-key"
        inference_key.write_text("isolated-runtime-inference-key")
        inference_key.chmod(0o400)
        source.update(
            {
                "OMNIGENT_SAAS_MODEL_RUN_INFERENCE_ENABLED": "true",
                "OMNIGENT_SAAS_LITELLM_INFERENCE_BASE_URL": "http://omnigent-litellm",
                "OMNIGENT_SAAS_LITELLM_INFERENCE_KEY_FILE": str(inference_key),
                "OMNIGENT_SAAS_LITELLM_RUN_ALIASES": "platform-model-" + "1" * 32,
                "OMNIGENT_SAAS_RUNTIME_VERSION": "isolated-version",
                "OMNIGENT_SAAS_UPSTREAM_REVISION": "a" * 40,
                "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": "isolated-schema",
                "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION": "isolated-contract",
            }
        )
    app, built_engines = build_platform_model_gateway(source)

    assert app is not None
    assert built_engines == tuple(engines)
    assert len(built_engines) == (4 if managed else 2)
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
