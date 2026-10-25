from __future__ import annotations

import asyncio
import json
import os
import stat
from contextlib import contextmanager, nullcontext
from datetime import timezone
from functools import partial
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.billing_metering_transport import MutualTlsBillingMeteringServer
from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.billing_models import BillingMeteringReceiptRecord, UsageEventRecord
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
)
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from saas.production.interactive_model_channel import (
    ModelChannelScope,
    SessionModelChannelMiddleware,
    SessionModelChannels,
    consume_host_model_channel,
    host_model_channel,
    prepare_host_model_channel,
)
from saas.production.model_run_credentials import ModelRunCredentialService
from saas.production.model_run_inference import LiteLLMRunInference
from saas.production.platform_model_gateway import (
    PlatformModelGateway,
    _UsageParser,
    create_platform_model_gateway_app,
)
from saas.production.platform_model_relay import PlatformModelRelay
from saas.runner_adapter.metering import (
    ManagedMeteringGrant,
    ProviderUsageMeter,
    build_metering_client,
)
from tests._helpers.polling import poll_until
from tests.saas import test_tenant_model_catalog_postgresql
from tests.saas.postgresql_retention import snapshot_nonempty_model_facts
from tests.saas.test_billing_metering_transport import _server_context, _ServerThread
from tests.saas.test_gateway_machine_metering import (
    _customer_prices,
    _register_metering_certificate,
)
from tests.saas.test_gateway_machine_metering_postgresql import _metering_login
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_interactive_model_channel import ORIGIN, _launch
from tests.saas.test_model_run_credentials_postgresql import _authenticator_login, _claim
from tests.saas.test_model_run_evidence import _enable_budget
from tests.saas.test_model_run_evidence_postgresql import (
    _billing_login,
)
from tests.saas.test_model_run_evidence_postgresql import (
    publication_protocol as publication_protocol,
)
from tests.saas.test_model_run_gateway import _document
from tests.saas.test_model_run_inference import _fund_synthetic_gateway_calls, _stream
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


def _real_litellm(publication, *, credential_name=None):
    path = os.environ.get("OMNIGENT_SAAS_TEST_LITELLM_RUNTIME_FILE")
    if path is None:
        return None
    document = json.loads(Path(path).read_text())
    assert urlsplit(document["proxy_url"]).hostname == "127.0.0.1"
    assert urlsplit(document["upstream_url"]).hostname == "127.0.0.1"

    async def provision():
        management = LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url=document["proxy_url"],
                management_key=document["management_key"],
                allowed_http_hosts=("127.0.0.1",),
                allowed_provider_base_urls=(document["provider_base"],),
            )
        )
        identifier = UUID(publication["deployment_id"])
        name = credential_name or "isolated-" + identifier.hex
        await management.create_deepseek_credential(name=name, api_key=document["provider_key"])
        await management.create_deepseek_deployment(
            deployment_id=identifier,
            alias=publication["deployment_alias"],
            model=publication["public_model_id"],
            credential_name=name,
            provider_base_url=document["provider_base"],
        )
        key = await management.create_inference_key(
            aliases=(publication["deployment_alias"],), key_alias=name, duration_seconds=3600
        )
        async with httpx.AsyncClient(trust_env=False) as client:
            denied = await client.get(
                document["proxy_url"] + "/model/info",
                headers={"Authorization": "Bearer " + key.value},
            )
            assert denied.status_code in {401, 403}
        return key.value

    document["inference_key"] = asyncio.run(provision())
    return document


@pytest.fixture(autouse=True)
def funded_publication(publication_protocol, monkeypatch):
    original = test_tenant_model_catalog_postgresql._fixture

    def configured():
        result = original()
        _fund_synthetic_gateway_calls(result[2], result[3])
        return result

    monkeypatch.setattr(test_tenant_model_catalog_postgresql, "_fixture", configured)


@contextmanager
def _run_binding(fixture, factory_state):
    if factory_state is not None:
        yield factory_state
        return
    f = fixture.base
    with _worker_logins(f) as workers, _authenticator_login(f) as authentication:
        _customer_prices(
            f.factory,
            actor=fixture.runtime.actor_id,
            tenant=fixture.runtime.tenant_id,
        )
        runtime, authorized, lease, _control, machine = _claim(
            fixture, workers, include_controller=True
        )
        credentials = ModelRunCredentialService(
            app_sessions=f.app_factory,
            authenticator_sessions=authentication,
            compatibility=runtime._resolver._compatibility_policy,
        )

        async def provision():
            return await asyncio.to_thread(credentials.issue, authorized, lease)

        from types import SimpleNamespace

        yield SimpleNamespace(
            authorized=authorized,
            lease=lease,
            credentials=credentials,
            machine=machine,
            provision=provision,
        )


def _exercise_run_inference(
    interactive_postgresql,
    tmp_path,
    send,
    *,
    factory_state=None,
    configuration_probe=None,
    unknown_retention=None,
    retained_checkpoint=None,
    billing_sessions=None,
    metering_sessions=None,
    metering_server_factory=None,
):
    f = interactive_postgresql.base
    with (
        _run_binding(interactive_postgresql, factory_state) as binding,
        (
            nullcontext(billing_sessions) if billing_sessions is not None else _billing_login(f)
        ) as billing,
        (
            nullcontext(metering_sessions) if metering_sessions is not None else _metering_login(f)
        ) as metering,
    ):
        authorized, lease = binding.authorized, binding.lease
        credentials, machine = binding.credentials, binding.machine
        issued = credentials.issue(authorized, lease)
        published = credentials.authorize(credentials.authenticate(issued.value))
        actual = (
            configuration_probe(published.configuration)
            if configuration_probe is not None
            else _real_litellm(published.configuration)
        )
        metering_path = tmp_path / "metering-pki"
        metering_path.mkdir()
        certificates, fingerprint = _register_metering_certificate(
            f.factory, machine["runner_id"], machine["connection_generation"], metering_path
        )
        _enable_budget(f.factory)
        with f.factory.begin() as db:
            config = db.get(ModelProviderConfigurationRecord, "deepseek")
            config.monthly_budget_microusd, config.per_tenant_daily_token_limit = (
                1_000_000,
                100_000,
            )
            expires = db.get(CapabilityTokenRecord, lease.capability_id).expires_at

        class Recorder:
            lost = False
            settlements = 0
            recovery_enabled = not send
            identities: set[str] = set()

            def __init__(self, authority):
                self.authority = authority

            def record_usage(self, **kwargs):
                return self.authority.record_usage(**kwargs)

            def gateway_usage(self, **kwargs):
                result = self.authority.gateway_usage(**kwargs)
                if kwargs["action"] == "settle":
                    self.settlements += 1
                    self.identities.add(
                        sha256(
                            json.dumps(kwargs, default=str, sort_keys=True).encode()
                        ).hexdigest()
                    )
                    if not self.lost or not self.recovery_enabled:
                        self.lost = True
                        raise RuntimeError("isolated post-commit acknowledgement loss")
                return result

        recorder = Recorder(BillingMeteringAuthority(metering))
        certificate_authority = RunnerCertificateAuthority(
            metering, accepted_trust_bundle_versions=("test-v1",)
        )
        server = (
            metering_server_factory(certificates, recorder)
            if metering_server_factory is not None
            else MutualTlsBillingMeteringServer(
                recorder, _server_context(certificates["server"]), certificate_authority
            )
        )
        thread = _ServerThread(server)
        thread.start()

        def restart_receiver():
            nonlocal server, thread
            if metering_server_factory is None:
                return
            port = server.port
            thread.close()
            thread = None
            server = metering_server_factory(certificates, recorder)
            replacement = _ServerThread(server, bind_port=port)
            replacement.start()
            thread = replacement
            assert server.port == port

        grant = ManagedMeteringGrant(
            session_id=published.execution_session_id,
            run_id=lease.run_id,
            runner_id=machine["runner_id"],
            capability_token=lease.capability_token,
            expires_at=expires.replace(tzinfo=timezone.utc),
            metering_base_url=f"https://127.0.0.1:{server.port}",
            expected_host="billing-metering.internal",
            ca_certificate_path=certificates["runner-0"].ca,
            client_certificate_path=certificates["runner-0"].certificate,
            client_key_path=certificates["runner-0"].private_key,
            spool_directory=tmp_path / "trusted-controller-spool",
        )
        meter = ProviderUsageMeter(
            grant=grant,
            client=build_metering_client(grant),
            gateway_managed=True,
            retry_interval_seconds=0.05,
        )
        calls = []
        responses = published.configuration["wire_api"] == "openai_responses"

        inference_key = (
            actual["inference_key"] if actual else "isolated-inference-only-not-a-real-key"
        )

        def observe(request):
            pending = list(grant.spool_directory.glob("*.pending.json"))
            assert len(pending) == 1
            assert "capability_token" not in pending[0].read_text()
            assert (
                json.loads(request.content)["model"] == published.configuration["deployment_alias"]
            )
            assert request.headers["Authorization"] == "Bearer " + inference_key
            calls.append(request)

        def upstream(request):
            observe(request)
            return httpx.Response(200, stream=httpx.ByteStream(_stream(responses)))

        async def observe_async(request):
            observe(request)

        def inference_client():
            return (
                httpx.AsyncClient(
                    trust_env=False, timeout=120, event_hooks={"request": [observe_async]}
                )
                if actual
                else httpx.AsyncClient(transport=httpx.MockTransport(upstream))
            )

        before = (
            httpx.get(actual["upstream_url"] + "/evidence", trust_env=False).json()
            if actual
            else None
        )

        gateway = PlatformModelGateway(
            tokens=None,
            configurations=None,
            pricing=None,
            budgets=ModelProviderBudgetAdmissionService(billing),
            run_credentials=credentials,
            run_inference=LiteLLMRunInference(
                actual["proxy_url"] if actual else "https://litellm.test",
                inference_key,
                (published.configuration["deployment_alias"],),
                billing,
                ("127.0.0.1",) if actual else (),
            ),
            client_factory=inference_client,
        )
        app = create_platform_model_gateway_app(gateway)
        if not send:

            def fail_before_send():
                raise OSError("isolated transport setup failure")

            gateway._client_factory = fail_before_send

        scope = ModelChannelScope(
            tenant_id=authorized.runtime.tenant_id,
            space_id=authorized.runtime.space_id,
            project_id=authorized.runtime.project_id,
            actor_id=authorized.runtime.actor_id,
            session_id=published.execution_session_id,
            partition_id=authorized.runtime.runtime_partition_id,
            official_session_id=authorized.session_id,
            publication_sha256=authorized.publication["snapshot_sha256"],
        )
        launch = _launch(scope)
        channel = host_model_channel(launch, scope=scope, public_origin=ORIGIN)
        clean, received = consume_host_model_channel(
            prepare_host_model_channel(launch, channel=channel), server_url=ORIGIN
        )
        assert received == channel and channel.secret_value not in json.dumps(
            clean.inference_config
        )
        assert lease.capability_token not in json.dumps(clean.inference_config)
        channels = SessionModelChannels(public_origin=ORIGIN)

        def new_relay():
            return PlatformModelRelay.for_run(
                run_id=lease.run_id,
                fence_token=lease.fence_token,
                credential_provider=binding.provision,
                metering=meter,
                capability=channel.secret_value,
                client_factory=lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app)),
            )

        relay = new_relay()
        try:
            with _channel_client(app, channels, scope, lease, relay) as client:
                result = client.post(
                    channel.base_url + ("/responses" if responses else "/chat/completions"),
                    json=_document(
                        published.configuration["public_model_id"], responses=responses, limit=32
                    ),
                    headers={"Authorization": "Bearer " + channel.secret_value},
                )
                assert result.status_code == (200 if send else 503), result.text
                if actual and send:
                    parser = _UsageParser(responses=responses)
                    parser.feed(result.content)
                    parser.finish()
                    assert parser.final_usage.total_tokens == 22
                    after = httpx.get(actual["upstream_url"] + "/evidence", trust_env=False).json()
                    assert len(after["requests"]) - len(before["requests"]) == 1
                elif send:
                    assert result.content == _stream(responses)
                retained, original_authority, known_reservation_id = None, {}, None
                if send:
                    poll_until(lambda: recorder.lost, timeout_s=10, interval_s=0.05)
                    assert not meter.flush(timeout_seconds=0)
                    assert recorder.lost
                    pending = list(grant.spool_directory.glob("*.pending.json"))
                    assert len(pending) == 1 and not pending[0].is_symlink()
                    pending_bytes = pending[0].read_bytes()
                    assert stat.S_IMODE(pending[0].stat().st_mode) == 0o600
                    reference = json.loads(pending_bytes)
                    known_reservation_id = UUID(reference["reservation_id"])
                    assert reference["version"] == 2
                    assert reference["run_id"] == str(grant.run_id)
                    assert reference["runner_id"] == str(grant.runner_id)
                    assert pending[0].name == reference["event_id"] + ".pending.json"
                    assert grant.capability_token.encode() not in pending_bytes
                    with f.engine.connect().execution_options(
                        isolation_level="REPEATABLE READ"
                    ) as connection:
                        retained = snapshot_nonempty_model_facts(connection)
                    original_authority = {
                        path: sha256(path.read_bytes()).hexdigest()
                        for path in (
                            grant.ca_certificate_path,
                            grant.client_certificate_path,
                            grant.client_key_path,
                        )
                    }
                    assert not meter.close(timeout_seconds=0)
                    assert pending[0].read_bytes() == pending_bytes
                    assert stat.S_IMODE(pending[0].stat().st_mode) == 0o600
                    if retained_checkpoint is not None:
                        retained_checkpoint("known_ack_lost", f.engine)
                    restart_receiver()
                    recorder.recovery_enabled = True
                    meter = ProviderUsageMeter(
                        grant=grant,
                        client=build_metering_client(grant),
                        gateway_managed=True,
                        retry_interval_seconds=0.05,
                    )
                assert meter.flush(timeout_seconds=10)
                assert recorder.lost and recorder.settlements >= 2
                if retained is not None:
                    with f.engine.connect().execution_options(
                        isolation_level="REPEATABLE READ"
                    ) as connection:
                        assert snapshot_nonempty_model_facts(connection) == retained
                    assert len(recorder.identities) == 1
                    assert all(
                        sha256(path.read_bytes()).hexdigest() == digest
                        for path, digest in original_authority.items()
                    )
                    assert len(calls) == 1
                    if actual:
                        assert before is not None
                        final = httpx.get(
                            actual["upstream_url"] + "/evidence", trust_env=False
                        ).json()
                        assert len(final["requests"]) - len(before["requests"]) == 1
            relay.close()
            relay = new_relay()
            if unknown_retention is not None:

                def uncertain_transport(request):
                    observe(request)
                    raise httpx.ReadTimeout("isolated post-admission outcome unknown")

                gateway._client_factory = lambda: httpx.AsyncClient(
                    transport=httpx.MockTransport(uncertain_transport)
                )
                with _channel_client(app, channels, scope, lease, relay) as client:
                    uncertain = client.post(
                        channel.base_url + ("/responses" if responses else "/chat/completions"),
                        json=_document(
                            published.configuration["public_model_id"],
                            responses=responses,
                            limit=32,
                        ),
                        headers={"Authorization": "Bearer " + channel.secret_value},
                    )
                    assert uncertain.status_code == 502
                    assert (
                        uncertain.json()["error"]["code"] == "platform_model_provider_unreachable"
                    )
                assert not meter.close(timeout_seconds=0)
                if retained_checkpoint is not None:
                    retained_checkpoint("unknown_hold", f.engine)
                restart_receiver()
                pending = list(grant.spool_directory.glob("*.pending.json"))
                assert len(pending) == 1 and not pending[0].is_symlink()
                unknown_bytes = pending[0].read_bytes()
                assert stat.S_IMODE(pending[0].stat().st_mode) == 0o600
                unknown_reference = json.loads(unknown_bytes)
                assert unknown_reference["run_id"] == str(grant.run_id)
                assert unknown_reference["runner_id"] == str(grant.runner_id)
                with f.engine.connect().execution_options(
                    isolation_level="REPEATABLE READ"
                ) as connection:
                    unknown_facts = snapshot_nonempty_model_facts(connection)
                with f.factory() as db:
                    hold = db.get(
                        ModelProviderBudgetReservationRecord,
                        UUID(unknown_reference["reservation_id"]),
                    )
                    assert hold.run_id == grant.run_id and hold.status == "uncertain"
                    assert hold.admitted_microusd > 0 and hold.admitted_tokens > 0
                    assert hold.settled_microusd == hold.released_microusd == 0
                    assert hold.settled_tokens == hold.released_tokens == 0
                    unknown_retention.update(
                        positive_hold_microusd=hold.admitted_microusd,
                        positive_hold_tokens=hold.admitted_tokens,
                        pending_sha256=sha256(unknown_bytes).hexdigest(),
                        pending_mode="0600",
                        nonempty_model_facts=unknown_facts,
                    )
                relay.close()
                meter = ProviderUsageMeter(
                    grant=grant,
                    client=build_metering_client(grant),
                    gateway_managed=True,
                    retry_interval_seconds=0.05,
                )
                assert not meter.flush(timeout_seconds=0.2)
                assert pending[0].read_bytes() == unknown_bytes
                assert stat.S_IMODE(pending[0].stat().st_mode) == 0o600
                with f.engine.connect().execution_options(
                    isolation_level="REPEATABLE READ"
                ) as connection:
                    assert snapshot_nonempty_model_facts(connection) == unknown_facts
                assert all(
                    sha256(path.read_bytes()).hexdigest() == digest
                    for path, digest in original_authority.items()
                )
                assert len(calls) == 2
                relay = new_relay()
            assert RunnerCertificateAuthority(
                f.factory, accepted_trust_bundle_versions=("test-v1",)
            ).revoke_certificate(fingerprint_sha256=fingerprint, reason="isolated revoked machine")
            with _channel_client(app, channels, scope, lease, relay) as client:
                denied = client.post(
                    channel.base_url + ("/responses" if responses else "/chat/completions"),
                    json=_document(
                        published.configuration["public_model_id"], responses=responses, limit=32
                    ),
                    headers={"Authorization": "Bearer " + channel.secret_value},
                )
                assert (
                    denied.status_code == 503
                    and denied.json()["error"]["code"] == "platform_model_metering_unavailable"
                )
                assert len(calls) == int(send) + int(unknown_retention is not None)
                assert len(list(grant.spool_directory.glob("*.pending.json"))) == int(
                    unknown_retention is not None
                )
            with f.factory() as db:
                assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == (
                    2 if send else 0
                )
                assert db.scalar(
                    sa.select(sa.func.count()).select_from(BillingMeteringReceiptRecord)
                ) == (2 if send else 0)
                assert (
                    db.scalar(sa.select(sa.func.sum(UsageEventRecord.customer_charge_minor))) or 0
                ) == (2 if send else 0)
                statement = sa.select(ModelProviderBudgetReservationRecord).where(
                    ModelProviderBudgetReservationRecord.purpose == "tenant_run"
                )
                if send:
                    assert known_reservation_id is not None
                    statement = statement.where(
                        ModelProviderBudgetReservationRecord.id == known_reservation_id
                    )
                budget = db.scalar(statement)
                assert budget.status == ("settled" if send else "released")
                assert budget.settled_tokens == ((22 if actual else 13) if send else 0)
                assert budget.run_id == lease.run_id
            return retained
        finally:
            relay.close()
            meter.close(timeout_seconds=0)
            if thread is not None:
                thread.close()


@pytest.mark.parametrize("send", [False, True], ids=["closed-before-send", "inference"])
def test_real_machine_relay_spools_before_egress_and_recovers_committed_ack(
    interactive_postgresql, tmp_path, send, record_property
):
    retained = _exercise_run_inference(interactive_postgresql, tmp_path, send)
    if send:
        record_property(
            "nonempty_model_facts_before_recovery", json.dumps(retained, sort_keys=True)
        )


def test_real_unknown_hold_and_original_pending_survive_meter_restart(
    interactive_postgresql, tmp_path, record_property
):
    retained = {}
    _exercise_run_inference(interactive_postgresql, tmp_path, True, unknown_retention=retained)
    record_property("unknown_hold_retained_after_restart", json.dumps(retained, sort_keys=True))


@contextmanager
def _channel_client(app, channels, scope, lease, relay):
    channel_app = SessionModelChannelMiddleware(app, channels=channels)
    with TestClient(channel_app) as client:
        client.portal.call(
            partial(
                channels.bind,
                scope,
                secret_value=relay.capability,
                run_id=lease.run_id,
                fence_token=lease.fence_token,
                relay=relay,
            )
        )
        try:
            yield client
        finally:
            assert client.portal.call(
                partial(
                    channels.suspend,
                    scope.session_id,
                    run_id=lease.run_id,
                    fence_token=lease.fence_token,
                )
            )
