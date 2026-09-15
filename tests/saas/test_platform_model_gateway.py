from __future__ import annotations

import ast
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import httpx
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
    build_platform_model_gateway,
    create_platform_model_gateway_app,
    load_platform_model_pricing,
)
from saas.production.platform_model_host import PlatformModelHostProcess
from saas.production.service_bindings import (
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
)
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority
from saas.runner_adapter.platform_models import (
    PLATFORM_MODEL_CREDENTIAL_ENV,
    PLATFORM_MODEL_CREDENTIAL_REFERENCE,
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


def test_provider_rejection_releases_budget_without_leaking_body() -> None:
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
    assert len(budgets.released) == 1
    assert not budgets.settled


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


def test_managed_host_injects_runner_only_session_token(
    monkeypatch,
    tmp_path: Path,
) -> None:
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=SIGNING_KEY,
        tenant_id=TENANT_ID,
    )
    captured: dict[str, str] = {}

    def fake_spawn(
        _self: HostProcess,
        environment: dict[str, str],
        _session_slug: str,
        _workspace: Path,
    ):
        captured["token"] = environment[PLATFORM_MODEL_CREDENTIAL_ENV]
        return cast(object, object()), tmp_path / "runner.log"

    monkeypatch.setattr(HostProcess, "_spawn_runner_proc", fake_spawn)
    host = PlatformModelHostProcess(
        HostIdentity(host_id="0123456789abcdef0123456789abcdef", name="model-host"),
        "https://control-plane.invalid",
        token_authority=authority,
        token_ttl_seconds=3600,
    )
    environment = {PRIMARY_SESSION_ID_ENV_VAR: str(SESSION_ID)}

    host._spawn_runner_proc(environment, "session-", tmp_path)

    assert PLATFORM_MODEL_CREDENTIAL_ENV not in environment
    assert authority.validate(captured["token"]).session_id == SESSION_ID


def test_pricing_policy_requires_canonical_read_only_file(tmp_path: Path) -> None:
    path = tmp_path / "pricing.json"
    document = {
        "catalog_sha256": "fc2923d2ab3ac92a2b1b16fef40cbcfbb139c3abcd9f4e7d3b3e3c34a8e8427c",
        "rates": [
            {
                "off_peak_input_cache_hit_microusd_per_million_tokens": 3_000,
                "off_peak_input_cache_miss_microusd_per_million_tokens": 150_000,
                "off_peak_output_microusd_per_million_tokens": 600_000,
                "peak_input_cache_hit_microusd_per_million_tokens": 6_000,
                "peak_input_cache_miss_microusd_per_million_tokens": 300_000,
                "peak_output_microusd_per_million_tokens": 1_200_000,
            }
        ],
        "revision": "pricing-20260914",
        "schema_version": 1,
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

    assert policy.revision == "pricing-20260914-v4.1"
    prices = policy.for_catalog(("deepseek-flash", "deepseek-v4-pro"))
    assert set(prices) == {"deepseek-flash", "deepseek-v4-pro"}
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

    assert provider["base_url"] == "http://omnigent-platform-model-gateway:8090/v1"
    assert provider["api_key"] == PLATFORM_MODEL_CREDENTIAL_REFERENCE
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
