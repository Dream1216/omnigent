"""Own-container physical Host contract; synthetic domain data is not production admission."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import ssl
import threading
import time
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import sqlalchemy as sa
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from saas.billing_metering_transport import MutualTlsBillingMeteringServer
from saas.compatibility import bind_runtime_context
from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.billing_models import UsageEventRecord
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.interactive_run_route import interactive_session_identity
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_routing_models import ModelDeploymentVersionRecord
from saas.control_plane.platform_models import ModelProviderConfigurationRecord
from saas.control_plane.scheduling_models import RunDispatchRecord, RunnerRegistrationRecord
from saas.production.external_host_credential import arm_external_host_credential
from saas.production.interactive_controller import ProductionInteractiveExecutor
from saas.production.interactive_controller_adapter import load_interactive_metering_credentials
from saas.production.interactive_driver import OfficialInteractiveDriver
from saas.production.interactive_model_channel import (
    SessionModelChannelMiddleware,
    SessionModelChannels,
)
from saas.production.interactive_recovery import InteractiveRecoveryJournal
from saas.production.model_run_inference import LiteLLMRunInference
from saas.production.platform_model_gateway import (
    PlatformModelGateway,
    create_platform_model_gateway_app,
)
from saas.production.runner_agent import ProductionRunnerAgent
from saas.production.runner_control import (
    DurableRunnerControlCertificateAuthorizer,
    MutualTlsRunnerControlClient,
    MutualTlsRunnerControlServer,
    ProductionRunnerMachineAuthority,
)
from saas.runner_adapter.metering import (
    ManagedMeteringGrant,
    ProviderUsageMeter,
    build_metering_client,
)
from tests.saas import test_interactive_execution_http
from tests.saas.test_billing_metering_transport import (
    _certificate_fixture,
    _client_context,
    _server_context,
    _ServerThread,
)
from tests.saas.test_gateway_machine_metering import (
    _customer_prices,
    _register_metering_certificate,
)
from tests.saas.test_http_cookie_auth import _login
from tests.saas.test_interactive_execution_http import _managed_create
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runner_lease import _admit, _controller, _register
from tests.saas.test_interactive_runtime import _runtime_authority
from tests.saas.test_model_run_credentials import _service
from tests.saas.test_model_run_evidence import _enable_budget
from tests.saas.test_model_run_inference import _fund_synthetic_gateway_calls, _setup

_ORIGIN = "https://next.test"


@pytest.fixture(autouse=True)
def physical_domain_database(tmp_path, monkeypatch):
    if os.environ.get("OMNIGENT_SAAS_PHYSICAL_TEST_EXCHANGE") is None:
        pytest.skip("requires the task-owned two-container TLS/Host process harness")
    build = test_interactive_execution_http._build_fastapi_app

    def file_database(*args, **kwargs):
        kwargs["database_url"] = "sqlite+pysqlite:///" + str(tmp_path / "domain.sqlite3")
        return build(*args, **kwargs)

    # A live Server and billing thread need the fixture's file-backed WAL mode.
    monkeypatch.setattr(test_interactive_execution_http, "_build_fastapi_app", file_database)


def _tls(root: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-controller-next.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("next.test")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert, private = root / "ca.pem", root / "server-key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    return cert, private


def _chat_stream(identifier: str) -> bytes:
    common = {
        "id": identifier,
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "deepseek-v4-pro",
    }
    frames = [
        {
            **common,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": "PHYSICAL_HOST_OK"},
                    "finish_reason": None,
                }
            ],
        },
        {**common, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        {
            **common,
            "choices": [],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 3,
                "total_tokens": 13,
                "prompt_cache_hit_tokens": 0,
                "prompt_cache_miss_tokens": 10,
            },
        },
    ]
    return (
        b"".join(("data: " + json.dumps(frame) + "\n\n").encode() for frame in frames)
        + b"data: [DONE]\n\n"
    )


def _wait(check, description: str, timeout: float = 90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("Timed out: " + description)


@pytest.fixture
def physical_https(interactive_http, tmp_path):
    configured = os.environ.get("OMNIGENT_SAAS_PHYSICAL_TEST_EXCHANGE")
    if configured is None:
        pytest.skip("requires the task-owned two-container TLS/Host process harness")
    exchange = Path(configured)
    assert exchange == Path("/exchange") and exchange.is_dir()
    f = interactive_http
    f.store._public_origin = _ORIGIN
    host_id, token = "c" * 32, secrets.token_urlsafe(32)
    host_store = f.dependencies["host_store"]
    with bind_runtime_context(f.runtime):
        host_store.upsert_on_connect(
            host_id, "isolated-controller-host", f.runtime.runtime_user_key
        )
        host_store.set_offline(host_id)
        arm_external_host_credential(
            host_store._engine, workspace_id=41, host_id=host_id, token=token, ttl_seconds=3600
        )
    channels = SessionModelChannels(public_origin=_ORIGIN)
    original = f.app.router.lifespan_context
    ready, state = threading.Event(), {}

    @asynccontextmanager
    async def lifespan(app):
        async with original(app):
            state["loop"] = asyncio.get_running_loop()
            ready.set()
            yield

    f.app.router.lifespan_context = lifespan
    certificate, private = _tls(tmp_path)
    (exchange / "ca.pem").write_bytes(certificate.read_bytes())
    host_token = exchange / "host-token"
    host_token.write_text(token)
    host_token.chmod(0o600)
    inner = SessionModelChannelMiddleware(f.app, channels=channels)
    bootstrap_events = []
    started_at = time.monotonic()

    async def observed_app(scope, receive, send):
        path = scope.get("path", "")
        tracked = (
            path.startswith("/v1/runners/") and path.endswith(("/token", "/tunnel"))
        ) or path.startswith("/internal/v1/model-channels/")
        status, response_body = None, bytearray()

        async def capture(message):
            nonlocal status
            event_type = message["type"]
            if tracked:
                row = {"path": path, "elapsed": time.monotonic() - started_at}
                if event_type == "http.response.start":
                    status = message["status"]
                    row.update(type=event_type, status=status)
                    bootstrap_events.append(row)
                elif event_type in {"websocket.accept", "websocket.close"}:
                    row.update(type=event_type, code=message.get("code"))
                    bootstrap_events.append(row)
                elif event_type == "http.response.body" and status is not None and status >= 400:
                    response_body.extend(message.get("body", b""))
                    if not message.get("more_body") and len(response_body) <= 4096:
                        error = json.loads(response_body).get("error", {})
                        row.update(type="public_error", code=error.get("code"))
                        if error.get("message") in {
                            "runner token minting is unsupported in this auth mode",
                            "runner token minting requires an auth provider",
                        }:
                            row["message"] = error["message"]
                        bootstrap_events.append(row)
                pending = exchange / "bootstrap-events.pending"
                pending.write_text(json.dumps(bootstrap_events))
                pending.replace(exchange / "bootstrap-events.json")
            await send(message)

        await inner(scope, receive, capture)

    server = uvicorn.Server(
        uvicorn.Config(
            observed_app,
            host="0.0.0.0",
            port=443,
            ssl_certfile=str(certificate),
            ssl_keyfile=str(private),
            log_level="warning",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, name="isolated-controller-https", daemon=True)
    thread.start()
    client = httpx.Client(
        base_url=_ORIGIN,
        trust_env=False,
        verify=ssl.create_default_context(cafile=str(certificate)),
        timeout=60,
    )
    try:
        assert ready.wait(30), "isolated HTTPS server lifespan did not start"
        _wait(lambda: server.started, "isolated HTTPS listener", timeout=20)
        ready_path = exchange / "ready.pending"
        ready_path.write_text(
            json.dumps(
                {
                    "host_id": host_id,
                    "workspace_id": 41,
                    "origin": _ORIGIN,
                    "scope": "isolated physical Host, not production fleet acceptance",
                }
            )
        )
        ready_path.replace(exchange / "ready.json")

        async def connected():
            with bind_runtime_context(f.runtime):
                return f.app.state.host_registry.get(host_id) is not None

        _wait(
            lambda: asyncio.run_coroutine_threadsafe(connected(), state["loop"]).result(5),
            "real Host WebSocket",
        )
        csrf = _login(client)
        yield SimpleNamespace(
            exchange=exchange,
            host_id=host_id,
            channels=channels,
            loop=state["loop"],
            client=client,
            headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        )
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=30)
        assert not thread.is_alive(), "isolated Server did not shut down"


@pytest.mark.timeout(300)
def test_real_fixed_host_launch_dispatch_and_stop(interactive_http, physical_https, tmp_path):
    _physical_execution(interactive_http, physical_https, tmp_path, full_agent=False)


@pytest.mark.timeout(300)
def test_real_fixed_host_runner_agent_lifecycle(interactive_http, physical_https, tmp_path):
    _physical_execution(interactive_http, physical_https, tmp_path, full_agent=True)


def _queued_setup(f, tmp_path):
    _fund_synthetic_gateway_calls(f.factory, f.publication_actor)
    _customer_prices(f.factory, actor=f.runtime.actor_id, tenant=f.runtime.tenant_id)
    scheduling, pool, domain, schema = _controller(f)
    run_id = _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="physical-agent-controller")
    authority = _runtime_authority(f, connection)
    service = _service(f, authority)
    certificates, fingerprint = _register_metering_certificate(
        f.factory, connection.runner_id, connection.connection_generation, tmp_path
    )
    _enable_budget(f.factory)
    with f.factory.begin() as db:
        configuration = db.get(ModelProviderConfigurationRecord, "deepseek")
        configuration.monthly_budget_microusd = 1_000_000
        configuration.per_tenant_daily_token_limit = 100_000
        alias = db.scalars(sa.select(ModelDeploymentVersionRecord.deployment_alias)).one()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("managed inference entered the legacy gateway")

    legacy = SimpleNamespace(validate=forbidden, load=forbidden)
    gateway = PlatformModelGateway(
        tokens=legacy,
        configurations=legacy,
        budgets=ModelProviderBudgetAdmissionService(f.factory),
        pricing=legacy,
        run_credentials=service,
        run_inference=LiteLLMRunInference(
            "https://litellm.test", "isolated-inference-only-not-a-real-key", (alias,), f.factory
        ),
    )
    return SimpleNamespace(
        run_id=run_id,
        connection=connection,
        authority=authority,
        service=service,
        certificates=certificates,
        fingerprint=fingerprint,
        gateway=gateway,
        scheduling=scheduling,
    )


def _physical_execution(f, physical, tmp_path, *, full_agent):
    exchange, host_id = physical.exchange, physical.host_id
    body = _managed_create(f)
    f.app.state.sandbox_config = None
    body.update(host_type="external", host_id=host_id, workspace="/workspace", initial_items=[])
    body.pop("workspaces")
    created = physical.client.post("/v1/sessions", json=body, headers=physical.headers)
    assert created.status_code == 201, created.text
    with bind_runtime_context(f.runtime):
        f.conversation = f.delegate.get_conversation(created.json()["id"])
    p = _queued_setup(f, tmp_path) if full_agent else asyncio.run(_setup(f, tmp_path))
    supplier_calls = []

    def supplier(request):
        supplier_calls.append(request)
        return httpx.Response(
            200, stream=httpx.ByteStream(_chat_stream("chat-" + str(len(supplier_calls))))
        )

    p.gateway._client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(supplier))
    gateway_app = create_platform_model_gateway_app(p.gateway)
    certificates = p.certificates
    certificate_authority = RunnerCertificateAuthority(
        f.factory, accepted_trust_bundle_versions=("test-v1",)
    )
    control_certificates = None
    if full_agent:
        control_root = tmp_path / "control-pki"
        control_root.mkdir()
        control_certificates = _certificate_fixture(control_root, (p.connection.runner_id,))
        certificate_authority.activate_certificate(
            runner_id=p.connection.runner_id,
            runner_connection_generation=p.connection.connection_generation,
            purpose="runner_control",
            certificate_der=x509.load_pem_x509_certificate(
                control_certificates["runner-0"].certificate.read_bytes()
            ).public_bytes(serialization.Encoding.DER),
            trust_bundle_version="test-v1",
        )
        paths = {
            "OMNIGENT_SAAS_INTERACTIVE_METERING_CA_FILE": str(certificates["runner-0"].ca),
            "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_CERTIFICATE_FILE": str(
                certificates["runner-0"].certificate
            ),
            "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_KEY_FILE": str(
                certificates["runner-0"].private_key
            ),
        }
        certificates["runner-0"].private_key.chmod(0o600)
        metering = load_interactive_metering_credentials(
            paths,
            runner_id=p.connection.runner_id,
            control_certificate=control_certificates["runner-0"].certificate,
        )
        assert metering.certificate == certificates["runner-0"].certificate
    billing = MutualTlsBillingMeteringServer(
        BillingMeteringAuthority(f.factory),
        _server_context(certificates["server"]),
        certificate_authority,
        expected_host="localhost",
    )
    meter_server = _ServerThread(billing)
    meter_server.start()
    journal = InteractiveRecoveryJournal(tmp_path / "controller-private")
    channels = physical.channels
    driver = OfficialInteractiveDriver(
        app=f.app,
        dependencies=SimpleNamespace(**{**f.dependencies, "conversation_store": f.delegate}),
        contract_version="0.2.0",
    )
    observations = []

    def observed(method, stage):
        async def invoke(*args, **kwargs):
            if stage == "prepare":
                kwargs["on_launch"] = observed(kwargs["on_launch"], "launch")
            observations.append({"stage": stage, "state": "started"})
            try:
                result = await method(*args, **kwargs)
            except Exception as error:
                observations.append(
                    {
                        "stage": stage,
                        "state": "failed",
                        "type": type(error).__name__,
                        "frames": [
                            {"file": row.filename, "line": row.lineno, "function": row.name}
                            for row in traceback.extract_tb(error.__traceback__)
                        ],
                    }
                )
                raise
            else:
                observations.append({"stage": stage, "state": "completed"})
                return result
            finally:
                (exchange / "driver-observations.json").write_text(json.dumps(observations))

        return invoke

    driver.prepare = observed(driver.prepare, "prepare")
    driver.dispatch = observed(driver.dispatch, "dispatch")

    async def authorize(lease):
        actual = await p.authority.authorize(lease)
        return actual, p.service.issue(actual, lease)

    def grant(actual, lease):
        return ManagedMeteringGrant(
            interactive_session_identity(
                actual.runtime.tenant_id,
                actual.runtime.space_id,
                actual.runtime.runtime_partition_id,
                actual.session_id,
            ),
            lease.run_id,
            p.connection.runner_id,
            lease.capability_token,
            lease.expires_at,
            f"https://127.0.0.1:{billing.port}",
            "localhost",
            certificates["runner-0"].ca,
            certificates["runner-0"].certificate,
            certificates["runner-0"].private_key,
            journal.root / "usage" / str(lease.run_id),
        )

    class ObservedMeter(ProviderUsageMeter):
        def prepare_gateway_call(self):
            try:
                return super().prepare_gateway_call()
            except Exception as error:
                (exchange / "meter-preflight-error.json").write_text(
                    json.dumps(
                        {
                            "type": type(error).__name__,
                            "code": getattr(error, "code", None),
                            "cause_type": type(error.__cause__).__name__,
                            "frames": [
                                {"file": row.filename, "line": row.lineno, "function": row.name}
                                for row in traceback.extract_tb(error.__traceback__)
                            ],
                        }
                    )
                )
                raise

    executor = ProductionInteractiveExecutor(
        authorize_model=authorize,
        grant_for_run=grant,
        driver=driver,
        journal=journal,
        channels=channels,
        connection_generation=p.connection.connection_generation,
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
        assert_authority=lambda: (
            None
        ),  # Domain/physical test, not production factory or fleet proof.
        verify_recovery=lambda record: asyncio.to_thread(p.authority.verify_recovery, record),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.ASGITransport(gateway_app)),
        meter_factory=lambda value: ObservedMeter(
            grant=value,
            client=build_metering_client(value),
            gateway_managed=True,
            retry_interval_seconds=0.05,
        ),
    )
    f.store.runtime_status_observer = driver.observe_runtime_status
    try:

        async def execute():
            if full_agent:
                machine = ProductionRunnerMachineAuthority(
                    p.scheduling,
                    ExecutionControlPlane(f.factory),
                    product_revision="c" * 40,
                    image_digest="sha256:" + "a" * 64,
                )
                control_server = MutualTlsRunnerControlServer(
                    machine,
                    _server_context(control_certificates["server"]),
                    DurableRunnerControlCertificateAuthorizer(certificate_authority),
                )
                await control_server.start()
                control = MutualTlsRunnerControlClient(
                    connect_host="localhost",
                    port=control_server.port,
                    server_name="localhost",
                    tls_context=_client_context(control_certificates["runner-0"]),
                    connection_generation=p.connection.connection_generation,
                    connection_token=p.connection.connection_token,
                )
                p.authority._control = control
                stop = asyncio.Event()
                agent = ProductionRunnerAgent(
                    control, executor, poll_interval_seconds=0.1, heartbeat_interval_seconds=5
                )
                task = asyncio.create_task(agent.run(stop), name="physical-runner-agent")
                try:
                    deadline = time.monotonic() + 150
                    while time.monotonic() < deadline:
                        if task.done():
                            await task
                            raise AssertionError("RunnerAgent exited before releasing the Run")
                        with f.factory() as db:
                            released = (
                                db.scalar(
                                    sa.select(RunDispatchRecord.status).where(
                                        RunDispatchRecord.run_id == p.run_id
                                    )
                                )
                                == "released"
                            )
                        if released:
                            break
                        await asyncio.sleep(0.1)
                    else:
                        raise AssertionError("RunnerAgent did not release its exact Run")
                    stop.set()
                    stats = await asyncio.wait_for(asyncio.shield(task), timeout=15)
                    assert (stats.claims, stats.completed, stats.failed, stats.released) == (
                        1,
                        1,
                        0,
                        1,
                    )
                    assert stats.physical_gc_failures == 0
                    (exchange / "runner-agent-stats.json").write_text(
                        json.dumps(
                            {
                                "claims": stats.claims,
                                "completed": stats.completed,
                                "failed": stats.failed,
                                "released": stats.released,
                                "physical_gc_failures": stats.physical_gc_failures,
                                "manual_heartbeat": False,
                                "control_mtls": True,
                                "production_factory": False,
                            }
                        )
                    )
                    record = journal.read(p.run_id)
                    assert record.phase == "terminal" and record.outcome == "succeeded"
                    assert await driver.stop(record)
                    await channels.forget(record.scope.session_id)
                except Exception as error:
                    (exchange / "runner-agent-error.json").write_text(
                        json.dumps(
                            {
                                "type": type(error).__name__,
                                "code": getattr(error, "code", None),
                                "frames": [
                                    {
                                        "file": row.filename,
                                        "line": row.lineno,
                                        "function": row.name,
                                    }
                                    for row in traceback.extract_tb(error.__traceback__)
                                ],
                            }
                        )
                    )
                    raise
                finally:
                    stop.set()
                    if not task.done():
                        try:
                            await asyncio.wait_for(asyncio.shield(task), timeout=15)
                        except TimeoutError:
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                    await control_server.aclose()
                return

            async def heartbeat():
                while True:
                    await p.authority._control.heartbeat_run(p.lease)
                    await asyncio.sleep(5)

            pulse = asyncio.create_task(heartbeat())
            try:
                result = await executor.execute(p.lease, cancellation=asyncio.Event())
            finally:
                pulse.cancel()
                await asyncio.gather(pulse, return_exceptions=True)
            prepared = await executor.prepare_finalization(p.lease, result=result)
            assert result == prepared == "succeeded"
            await executor.prepare_terminal_transition(p.lease)
            await executor.finalize(p.lease, result=result)
            record = journal.read(p.lease.run_id)
            assert record.host_id == host_id and record.official_runner_id
            assert await driver.stop(record), "real Host did not acknowledge stopping its Runner"
            await channels.forget(record.scope.session_id)

        asyncio.run_coroutine_threadsafe(execute(), physical.loop).result(180)
        with f.factory() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 2
            if full_agent:
                assert db.get(RunRecord, p.run_id).status == "succeeded"
                runner = db.get(RunnerRegistrationRecord, p.connection.runner_id)
                assert runner.active_leases == 0
                assert (
                    db.scalar(
                        sa.select(RunDispatchRecord.status).where(
                            RunDispatchRecord.run_id == p.run_id
                        )
                    )
                    == "released"
                )
            else:
                assert db.get(RunRecord, p.lease.run_id).status == "running"
        assert len(supplier_calls) == 1
        with bind_runtime_context(f.runtime):
            items = f.delegate.list_items(f.conversation.id, limit=100)
        assert "PHYSICAL_HOST_OK" in str(items)
        (exchange / "result.json").write_text(
            json.dumps(
                {
                    "passed": True,
                    "supplier_calls": 1,
                    "physical_host": True,
                    "production_pki": False,
                    "real_litellm": False,
                    "full_runner_agent": full_agent,
                    "production_factory": False,
                    "scope": "real Host/Runner/SDK; SQLite and MockTransport supplier",
                }
            )
        )
    finally:
        asyncio.run_coroutine_threadsafe(executor.shutdown(), physical.loop).result(30)
        meter_server.close()
        journal.close()
