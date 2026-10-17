from __future__ import annotations

import asyncio
import copy
import json
import secrets
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from omnigent.debug_logging import PRIMARY_SESSION_ID_ENV_VAR
from omnigent.host.connect import HostProcess
from omnigent.host.frames import (
    HostLaunchRunnerFrame,
    HostLaunchRunnerResultFrame,
    encode_host_frame,
)
from omnigent.host.identity import HostIdentity
from omnigent.runtime.telemetry import _payload_to_attribute
from saas.production import platform_model_host, platform_model_sandbox_host
from saas.production.interactive_model_channel import (
    CHANNEL_CONTROL_KEY,
    ModelChannelScope,
    SessionModelChannelMiddleware,
    SessionModelChannels,
    channel_url,
    consume_host_model_channel,
    host_model_channel,
    prepare_host_model_channel,
)
from saas.production.model_run_credentials import IssuedModelRunCredential
from saas.production.platform_model_host import CONTROLLER_BOUND_ENV, PlatformModelHostProcess
from saas.production.platform_model_relay import PlatformModelRelay
from saas.runner_adapter.metering import ProviderUsageMeter
from saas.runner_adapter.platform_models import (
    PLATFORM_MODEL_CREDENTIAL_ENV,
    PLATFORM_MODEL_RELAY_BASE_URL_ENV,
)
from tests.saas.test_gateway_usage_delivery import ReferenceClient
from tests.saas.test_provider_usage_metering import _grant

ORIGIN = "https://model-channel.invalid"


def _scope():
    return ModelChannelScope(*(uuid4() for _ in range(6)), uuid4().hex, "a" * 64)


def _launch(scope):
    endpoint = channel_url(ORIGIN, scope.session_id)
    configuration = {
        "providers": {
            "platform-deepseek": {
                "kind": "gateway",
                "openai": {
                    "base_url": endpoint,
                    "api_key_ref": "env:" + PLATFORM_MODEL_CREDENTIAL_ENV,
                    "wire_api": "responses",
                },
            }
        },
        "inference": {
            "harnesses": {
                "codex": {
                    "provider": "platform-deepseek",
                    "default_model": "synthetic-channel-model",
                    "model_allowlist": ["synthetic-channel-model"],
                }
            }
        },
    }
    return HostLaunchRunnerFrame(
        "request",
        secrets.token_urlsafe(32),
        "/workspace",
        scope.official_session_id,
        "codex",
        configuration,
    )


def _prepared(scope):
    frame = _launch(scope)
    channel = host_model_channel(frame, scope=scope, public_origin=ORIGIN)
    return prepare_host_model_channel(frame, channel=channel), channel


@pytest.fixture
def meter_factory(tmp_path):
    meters = []

    def create(run_id):
        grant = replace(_grant(tmp_path), run_id=run_id, spool_directory=tmp_path / run_id.hex)
        meter = ProviderUsageMeter(
            grant=grant, client=ReferenceClient(available=True), gateway_managed=True
        )
        meters.append(meter)
        return meter

    yield create
    for meter in meters:
        meter.close(timeout_seconds=0)


def _relay(run_id, capability, requests, *, meter=None, handler=None):
    async def credential():
        # Component fixture, not proof of a production lease, PKI or database grant.
        return IssuedModelRunCredential(
            "mrt_" + run_id.hex * 2, datetime.now(timezone.utc) + timedelta(hours=8), run_id, 1, 1
        )

    def upstream(request):
        requests.append(request)
        return (
            handler(request)
            if handler
            else httpx.Response(200, stream=httpx.ByteStream(b'data: {"done":true}\n\n'))
        )

    return PlatformModelRelay.for_run(
        run_id=run_id,
        fence_token=1,
        capability=capability,
        metering=meter,
        credential_provider=credential,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
    )


def test_handoff_uses_existing_redacted_binding_without_nested_secrets():
    scope = _scope()
    frame = _launch(scope)
    original = copy.deepcopy(frame)
    channel = host_model_channel(frame, scope=scope, public_origin=ORIGIN)
    prepared = prepare_host_model_channel(frame, channel=channel)
    clean, consumed = consume_host_model_channel(prepared, server_url=ORIGIN)
    assert frame == original == clean
    assert consumed == channel
    assert channel.secret_value != frame.binding_token
    assert channel.secret_value not in encode_host_frame(prepared)
    assert channel.secret_value not in repr(channel)
    payload = _payload_to_attribute(json.loads(encode_host_frame(prepared)))
    assert frame.binding_token not in payload
    assert channel.secret_value not in payload
    assert CHANNEL_CONTROL_KEY not in clean.inference_config
    next_process = replace(frame, binding_token=secrets.token_urlsafe(32))
    assert host_model_channel(next_process, scope=scope, public_origin=ORIGIN) != channel


@pytest.mark.parametrize(
    "change",
    [
        "foreign_origin",
        "http",
        "inline_key",
        "wrong_reference",
        "wrong_session",
        "extra_secret",
        "wrong_provider",
        "invalid_binding",
    ],
)
def test_host_rejects_untrusted_model_channel_configuration(change):
    frame, _ = _prepared(_scope())
    config = frame.inference_config
    api = config["providers"]["platform-deepseek"]["openai"]
    if change == "foreign_origin":
        config[CHANNEL_CONTROL_KEY]["base_url"] = api["base_url"] = api["base_url"].replace(
            ORIGIN, "https://other.invalid"
        )
    elif change == "http":
        config[CHANNEL_CONTROL_KEY]["base_url"] = api["base_url"] = api["base_url"].replace(
            "https:", "http:"
        )
    elif change == "inline_key":
        api["api_key"] = "not-a-real-secret"
    elif change == "wrong_reference":
        api["api_key_ref"] = "env:FOREIGN_KEY"
    elif change == "wrong_session":
        config[CHANNEL_CONTROL_KEY]["session_id"] = uuid4().hex
    elif change == "extra_secret":
        config[CHANNEL_CONTROL_KEY]["secret_value"] = "must-not-be-accepted"
    elif change == "wrong_provider":
        config["providers"]["foreign"] = config["providers"]["platform-deepseek"]
        config["inference"]["harnesses"]["codex"]["provider"] = "foreign"
    else:
        frame.binding_token = "not-an-official-binding"
    with pytest.raises(ValueError):
        consume_host_model_channel(frame, server_url=ORIGIN)


@pytest.mark.asyncio
async def test_cached_agent_channel_survives_two_run_handover_without_replaying_input(
    meter_factory,
):
    scope = _scope()
    _, channel = _prepared(scope)
    channels = SessionModelChannels(public_origin=ORIGIN)
    app = SessionModelChannelMiddleware(FastAPI(), channels=channels)
    calls = []
    headers = {"Authorization": "Bearer " + channel.secret_value}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        for index, path in enumerate(("responses", "chat/completions")):
            run = uuid4()
            relay = _relay(run, channel.secret_value, calls, meter=meter_factory(run))
            await channels.bind(
                scope, secret_value=channel.secret_value, run_id=run, fence_token=1, relay=relay
            )
            result = await client.post(
                channel.base_url + "/" + path,
                headers=headers,
                json={"input": f"do not replay task {index}"},
            )
            assert result.status_code == 200
            assert result.content == b'data: {"done":true}\n\n'
            assert calls[-1].headers["Authorization"] == "Bearer mrt_" + run.hex * 2
            assert channel.secret_value not in str(calls[-1].headers)
            assert await channels.suspend(scope.session_id, run_id=run, fence_token=1)
            assert (
                await client.post(channel.base_url + "/responses", headers=headers, json={})
            ).status_code == 503
        assert len(calls) == 2


@pytest.mark.asyncio
async def test_inflight_timeout_keeps_old_run_barrier_and_blocks_new_binding(meter_factory):
    scope = _scope()
    _, channel = _prepared(scope)
    channels = SessionModelChannels(public_origin=ORIGIN)
    started, finish = asyncio.Event(), asyncio.Event()
    calls = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            started.set()
            await finish.wait()
            yield b"old-run-only"

    run, next_run = uuid4(), uuid4()
    relay = _relay(
        run,
        channel.secret_value,
        calls,
        meter=meter_factory(run),
        handler=lambda _: httpx.Response(200, stream=Stream()),
    )
    await channels.bind(
        scope, secret_value=channel.secret_value, run_id=run, fence_token=1, relay=relay
    )
    app = SessionModelChannelMiddleware(FastAPI(), channels=channels)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
        headers = {"Authorization": "Bearer " + channel.secret_value}
        pending = asyncio.create_task(
            client.post(channel.base_url + "/responses", headers=headers, json={})
        )
        try:
            await asyncio.wait_for(started.wait(), 2)
            assert not await channels.suspend(
                scope.session_id, run_id=run, fence_token=1, timeout=0.01
            )
            assert (
                await client.post(channel.base_url + "/responses", headers=headers, json={})
            ).status_code == 503
            with pytest.raises(ValueError, match="busy"):
                await channels.bind(
                    scope,
                    secret_value=channel.secret_value,
                    run_id=next_run,
                    fence_token=1,
                    relay=_relay(next_run, channel.secret_value, calls),
                )
            with pytest.raises(ValueError, match="fence_changed"):
                await channels.suspend(scope.session_id, run_id=run, fence_token=2)
        finally:
            finish.set()
            result = await pending
            assert await channels.suspend(scope.session_id, run_id=run, fence_token=1)
        assert result.content == b"old-run-only"
        assert len(calls) == 1


@pytest.mark.asyncio
async def test_http_boundary_rejects_browser_and_cross_session_credentials(meter_factory):
    scope = _scope()
    _, channel = _prepared(scope)
    channels = SessionModelChannels(public_origin=ORIGIN)
    run, calls = uuid4(), []
    await channels.bind(
        scope,
        secret_value=channel.secret_value,
        run_id=run,
        fence_token=1,
        relay=_relay(run, channel.secret_value, calls, meter=meter_factory(run)),
    )
    app = FastAPI()

    @app.get("/normal")
    def normal():
        return {"normal": True}

    wrapped = SessionModelChannelMiddleware(app, channels=channels)
    auth = ("authorization", "Bearer " + channel.secret_value)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(wrapped), base_url=ORIGIN
    ) as client:
        cases = [
            ([], ""),
            ([auth, auth], ""),
            ([auth, ("cookie", "session=untrusted")], ""),
            ([auth, ("origin", "https://foreign.invalid")], ""),
            ([auth], "?run_id=" + str(run)),
            ([("authorization", "Bearer " + secrets.token_urlsafe(32))], ""),
        ]
        for headers, query in cases:
            result = await client.post(
                channel.base_url + "/responses" + query, headers=headers, json={}
            )
            assert result.status_code == 403
            assert channel.secret_value not in result.text
        foreign = channel_url(ORIGIN, uuid4())
        assert (
            await client.post(foreign + "/responses", headers=[auth], json={})
        ).status_code == 403
        assert (
            await client.get(channel.base_url + "/responses", headers=[auth])
        ).status_code == 403
        assert (
            await client.post(channel.base_url + "/refresh", headers=[auth], json={})
        ).status_code == 404
        assert (await client.get("/normal")).json() == {"normal": True}
    assert not calls
    assert await channels.suspend(scope.session_id, run_id=run, fence_token=1)


@pytest.mark.asyncio
async def test_unmetered_or_misbound_run_cannot_open_a_session_channel(meter_factory):
    scope = _scope()
    _, channel = _prepared(scope)
    channels = SessionModelChannels(public_origin=ORIGIN)
    run = uuid4()
    unmetered = _relay(run, channel.secret_value, [])
    with pytest.raises(ValueError, match="run_invalid"):
        await channels.bind(
            scope, secret_value=channel.secret_value, run_id=run, fence_token=1, relay=unmetered
        )
    metered = _relay(run, channel.secret_value, [], meter=meter_factory(run))
    with pytest.raises(ValueError, match="run_invalid"):
        await channels.bind(
            scope, secret_value=channel.secret_value, run_id=run, fence_token=2, relay=metered
        )
    await channels.bind(
        scope, secret_value=channel.secret_value, run_id=run, fence_token=1, relay=metered
    )
    assert await channels.suspend(scope.session_id, run_id=run, fence_token=1)
    with pytest.raises(ValueError, match="scope_changed"):
        channels.restore(replace(scope, tenant_id=uuid4()), channel.secret_value)


@pytest.mark.asyncio
@pytest.mark.parametrize("spawn_failure", [False, True])
async def test_managed_host_strips_metadata_and_injects_only_session_capability(
    tmp_path, monkeypatch, spawn_failure
):
    scope = _scope()
    frame, channel = _prepared(scope)
    host = PlatformModelHostProcess(
        HostIdentity(uuid4().hex, "channel-host"),
        ORIGIN,
        token_authority=None,
        token_ttl_seconds=28800,
        controller_bound=True,
    )
    assert "saas.model-channel.v1" in host._hello_capabilities()
    assert "saas.model-channel.v1" not in HostProcess._hello_capabilities(host)
    captured = []

    def spawn(_self, env, *_args):
        captured.append(dict(env))
        if spawn_failure:
            raise OSError("synthetic spawn failure")
        return object(), tmp_path / "runner.log"

    async def official_launch(_self, clean):
        assert CHANNEL_CONTROL_KEY not in clean.inference_config
        path = tmp_path / "persisted-config.json"
        path.write_text(json.dumps(clean.inference_config))
        assert channel.secret_value not in path.read_text()
        env = {PRIMARY_SESSION_ID_ENV_VAR: scope.official_session_id}
        try:
            host._spawn_runner_proc(env, "session-", tmp_path)
        finally:
            assert PLATFORM_MODEL_CREDENTIAL_ENV not in env
        return HostLaunchRunnerResultFrame(frame.request_id, "launched", "synthetic-runner")

    monkeypatch.setattr(HostProcess, "_spawn_runner_proc", spawn)
    monkeypatch.setattr(HostProcess, "_handle_launch", official_launch)
    if spawn_failure:
        with pytest.raises(OSError):
            await host._handle_launch(frame)
    else:
        assert (await host._handle_launch(frame)).status == "launched"
    assert captured == [
        {
            PRIMARY_SESSION_ID_ENV_VAR: scope.official_session_id,
            PLATFORM_MODEL_CREDENTIAL_ENV: channel.secret_value,
        }
    ]
    assert PLATFORM_MODEL_RELAY_BASE_URL_ENV not in captured[0]
    assert not host._pending_model_channels
    with pytest.raises(OSError, match="unavailable"):
        host._spawn_runner_proc(
            {PRIMARY_SESSION_ID_ENV_VAR: scope.official_session_id}, "session-", tmp_path
        )


@pytest.mark.parametrize("sandbox", [False, True])
def test_both_host_entrypoints_enable_managed_mode_without_root_signing_key(monkeypatch, sandbox):
    captured = []

    def start(server_url, *, host_factory):
        host = host_factory(HostIdentity(uuid4().hex, "managed-host"), server_url)
        assert host._controller_bound and host._platform_model_tokens is None
        captured.append(host)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("managed mode must not load or stage root signing authority")

    monkeypatch.setattr(platform_model_host, "run_host_process", start)
    monkeypatch.setattr(platform_model_host, "activate_managed_host_environment", lambda: None)
    monkeypatch.setattr(platform_model_host, "_secret_file", forbidden)
    monkeypatch.setattr(platform_model_sandbox_host, "stage_platform_model_key", forbidden)
    environment = {
        CONTROLLER_BOUND_ENV: "true",
        "OMNIGENT_SAAS_SERVER_URL": ORIGIN,
        "OMNIGENT_MANAGED_SERVER_URL": ORIGIN,
    }
    if sandbox:
        platform_model_sandbox_host.run_platform_model_sandbox_host(environment)
    else:
        platform_model_host.run_platform_model_host(environment)
    assert len(captured) == 1


@pytest.mark.asyncio
async def test_duplicate_launch_cannot_remove_an_inflight_session_channel(tmp_path, monkeypatch):
    scope = _scope()
    frame, channel = _prepared(scope)
    host = PlatformModelHostProcess(
        HostIdentity(uuid4().hex, "managed-host"),
        ORIGIN,
        token_authority=None,
        token_ttl_seconds=28800,
        controller_bound=True,
    )
    started, finish = asyncio.Event(), asyncio.Event()
    calls = []

    def spawn(_self, env, *_args):
        calls.append(env[PLATFORM_MODEL_CREDENTIAL_ENV])
        return object(), tmp_path / "runner.log"

    async def official_launch(_self, clean):
        host._spawn_runner_proc(
            {PRIMARY_SESSION_ID_ENV_VAR: clean.session_id}, "session-", tmp_path
        )
        started.set()
        await finish.wait()
        return HostLaunchRunnerResultFrame(clean.request_id, "launched", "synthetic-runner")

    monkeypatch.setattr(HostProcess, "_spawn_runner_proc", spawn)
    monkeypatch.setattr(HostProcess, "_handle_launch", official_launch)
    first = asyncio.create_task(host._handle_launch(frame))
    try:
        await asyncio.wait_for(started.wait(), 2)
        refused = await host._handle_launch(frame)
        assert refused.status == "failed"
        assert refused.error_code == "interactive_model_channel_unavailable"
        assert scope.official_session_id in host._pending_model_channels
    finally:
        finish.set()
        assert (await first).status == "launched"
    assert calls == [channel.secret_value] and not host._pending_model_channels


@pytest.mark.parametrize(
    "configuration",
    [
        {CONTROLLER_BOUND_ENV: "1"},
        {
            CONTROLLER_BOUND_ENV: "true",
            "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE": "/must-not-read",
        },
        {CONTROLLER_BOUND_ENV: "true", "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID": str(uuid4())},
        {CONTROLLER_BOUND_ENV: "true", "OMNIGENT_SAAS_SERVER_URL": "http://not-tls.invalid"},
    ],
)
def test_managed_host_rejects_ambiguous_mode_or_signing_authority(configuration, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid authority must not start a Host or read secrets")

    monkeypatch.setattr(platform_model_host, "run_host_process", forbidden)
    monkeypatch.setattr(platform_model_host, "_secret_file", forbidden)
    with pytest.raises(platform_model_host.PlatformModelHostConfigurationError):
        platform_model_host.run_platform_model_host(
            {"OMNIGENT_SAAS_SERVER_URL": ORIGIN, **configuration}
        )


@pytest.mark.asyncio
async def test_managed_host_missing_channel_fails_before_official_launch(monkeypatch):
    host = PlatformModelHostProcess(
        HostIdentity(uuid4().hex, "managed-host"),
        ORIGIN,
        token_authority=None,
        token_ttl_seconds=28800,
        controller_bound=True,
    )

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("must reject before launch")

    monkeypatch.setattr(HostProcess, "_handle_launch", forbidden)
    result = await host._handle_launch(_launch(_scope()))
    assert result.status == "failed"
    assert result.error_code == "interactive_model_channel_unavailable"


@pytest.mark.asyncio
async def test_managed_channel_never_promotes_a_missing_harness_cli(monkeypatch):
    host = PlatformModelHostProcess(
        HostIdentity(uuid4().hex, "managed-host"),
        ORIGIN,
        token_authority=None,
        token_ttl_seconds=28800,
        controller_bound=True,
    )
    frame, _ = _prepared(_scope())
    monkeypatch.setattr(
        "omnigent.onboarding.harness_install.missing_harness_cli", lambda _harness: "codex"
    )
    result = await host._handle_launch(frame)
    assert result.status == "failed" and result.error_code == "harness_not_configured"
    assert not host._pending_model_channels


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.invalid",
        "https://example.invalid:8443",
        "https://user:password@example.invalid",
        "https://example.invalid/v1",
        "https://example.invalid?token=bad",
        "https://example.invalid\n",
    ],
)
def test_channel_origin_must_be_exact_trusted_https(origin):
    with pytest.raises(ValueError):
        SessionModelChannels(public_origin=origin)
