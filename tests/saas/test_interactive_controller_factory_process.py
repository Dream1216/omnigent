"""Own-container controller composition; local PKI/Fleet are not production receipts."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import ssl
import subprocess
import threading
import traceback
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
import sqlalchemy as sa
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import sessionmaker

from omnigent.stores.host_store import HostStore
from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore
from omnigent.stores.project_store.sqlalchemy_store import SqlAlchemyProjectStore
from saas.application import create_omnigent_saas_app
from saas.billing_metering_transport import MutualTlsBillingMeteringServer
from saas.compatibility import OmnigentStoreAdapter, bind_runtime_context
from saas.control_plane import (
    IdentityManagementService,
    MembershipLifecycleService,
    PasswordCredentialService,
    SaasCookieConfig,
    SqlAlchemyContextResolver,
    create_saas_http_integration,
)
from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.billing_models import BillingMeteringReceiptRecord, UsageEventRecord
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord, TaskRecord
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_deployments import compile_stored_model_deployment
from saas.control_plane.model_routing_models import (
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelPublicationVersionRecord,
    ModelRunTokenRecord,
)
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
    ModelProviderMonthlyBudgetRecord,
    ModelProviderTenantDailyUsageRecord,
)
from saas.control_plane.resolver import load_runtime_compatibility_policy
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import RunDispatchRecord, RunnerRegistrationRecord
from saas.production.external_host_credential import arm_external_host_credential
from saas.production.interactive_controller_adapter import ProductionInteractiveControllerAdapter
from saas.production.interactive_execution import InteractiveConversationStore
from saas.production.interactive_runtime import ProductionInteractiveRuntimeFactory
from saas.production.litellm_configuration_attestation import LiteLLMConfigurationAttestor
from saas.production.model_run_credentials import ModelRunCredentialService
from saas.production.model_run_inference import LiteLLMRunInference
from saas.production.platform_model_gateway import (
    PlatformModelGateway,
    create_platform_model_gateway_app,
)
from saas.production.runner_control import (
    DurableRunnerControlCertificateAuthorizer,
    MutualTlsRunnerControlServer,
    ProductionRunnerMachineAuthority,
    TlsRunnerControlReadinessServer,
)
from saas.production.runner_readiness import assert_postgresql_runner_fleet_ready
from tests.saas import test_model_deployments, test_tenant_model_catalog_postgresql
from tests.saas.test_billing_metering_transport import _server_context, _ServerThread
from tests.saas.test_execution_control_plane import _execution_fixture
from tests.saas.test_gateway_machine_metering import (
    _customer_prices,
    _register_metering_certificate,
)
from tests.saas.test_gateway_machine_metering_postgresql import _metering_login
from tests.saas.test_interactive_controller_process import _tls, _wait
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_http import _message, _queued_worker, _scheduling
from tests.saas.test_interactive_execution_postgresql import _interactive_postgresql_case
from tests.saas.test_interactive_factory_fleet_postgresql import _application_logins, _signed_fleet
from tests.saas.test_model_connections import _KEY
from tests.saas.test_model_run_evidence import _enable_budget
from tests.saas.test_model_run_evidence_postgresql import _billing_login
from tests.saas.test_model_run_gateway import _document
from tests.saas.test_model_run_inference import _fund_synthetic_gateway_calls
from tests.saas.test_model_run_inference_postgresql import _real_litellm
from tests.saas.test_official_http_integration import _official_dependencies
from tests.saas.test_production_runner_control import _certificates
from tests.saas.test_production_runner_control import _server_context as _control_server_context
from tests.server.helpers import build_agent_bundle

ORIGIN = "https://next.test"


@contextmanager
def _listener(app, *, port=0, certificate=None, key=None):
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="0.0.0.0",
            port=port,
            ssl_certfile=str(certificate) if certificate else None,
            ssl_keyfile=str(key) if key else None,
            log_level="warning",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        _wait(lambda: server.started or not thread.is_alive(), "owned HTTP listener", timeout=30)
        assert thread.is_alive() and server.started
        yield server
    finally:
        server.should_exit = True
        thread.join(timeout=30)
        assert not thread.is_alive(), "owned HTTP listener did not shut down"


def _readiness_tls(root):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "readiness.svc")])
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("readiness.svc")]), False)
        .sign(key, hashes.SHA256())
    )
    cert, private = root / "readiness.pem", root / "readiness-key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, private)
    return context, cert


def _private(path, value):
    path.write_text(value)
    path.chmod(0o400)
    return str(path)


def _physical_controller(case, db_uri, tmp_path, monkeypatch):
    exchange = Path(os.environ["OMNIGENT_SAAS_PHYSICAL_TEST_EXCHANGE"])
    assert exchange == Path("/exchange")
    monkeypatch.setenv("OMNIGENT_WS_ALLOWED_ORIGINS", ORIGIN)
    scenario = getattr(case, "scenario", "single")
    assert scenario in {
        "single",
        "tools_cross_run",
        "cancel_before_admission",
        "cancel_unknown_stream",
    }
    if scenario == "tools_cross_run":
        command = test_model_deployments._command
        monkeypatch.setattr(
            test_model_deployments, "_command", lambda: replace(command(), max_output_tokens=256)
        )
        credential_init = ModelRunCredentialService.__init__

        def short_lived_credentials(self, **kwargs):
            # Observe natural expiry without altering immutable credential records.
            credential_init(self, **kwargs, ttl=timedelta(seconds=90))

        monkeypatch.setattr(ModelRunCredentialService, "__init__", short_lived_credentials)
    original = test_tenant_model_catalog_postgresql._fixture

    def funded():
        result = original()
        _fund_synthetic_gateway_calls(result[2], result[3])
        return result

    monkeypatch.setattr(test_tenant_model_catalog_postgresql, "_fixture", funded)
    with _application_logins(case) as applications, _worker_logins(case) as workers:
        factory, _, scope, request = _execution_fixture(case.engine)
        base = SimpleNamespace(
            engine=case.engine,
            factory=factory,
            scope=scope,
            context=request,
            app=applications["app"],
            app_factory=sessionmaker(applications["app"], expire_on_commit=False),
        )
        with _billing_login(base) as billing, _metering_login(base) as metering:
            manifest = json.loads((case.root / "saas/upstream-baseline.json").read_text())
            fixture = _interactive_postgresql_case(
                base,
                monkeypatch,
                placement_id=case.placement_id,
                product_revision=case.product_revision,
                upstream_revision=manifest["upstream_revision"],
                schema_revision=case.schema_revision,
                runtime_version=manifest["upstream_version"],
            )
            runtime = fixture.runtime
            _customer_prices(factory, actor=runtime.actor_id, tenant=runtime.tenant_id)
            _scheduling(factory, runtime, runtime.project_id, pool_id=case.pool_id)
            dependencies = _official_dependencies(db_uri, tmp_path)
            permissions, projects = (
                SqlAlchemyPermissionStore(db_uri),
                SqlAlchemyProjectStore(db_uri),
            )
            host_store = HostStore(db_uri)
            delegate = dependencies["conversation_store"]
            template = fixture.conversation
            with bind_runtime_context(runtime):
                projects.create(
                    template.project_id, "Physical controller", runtime.runtime_user_key
                )
                dependencies["agent_store"].create(
                    "b" * 32, "controller-agent", "controller/bundle"
                )
                host_store.upsert_on_connect(
                    "c" * 32, "isolated-controller-host", runtime.runtime_user_key
                )
                host_store.set_offline("c" * 32)
            dependencies["artifact_store"].put(
                "controller/bundle",
                build_agent_bundle(
                    name="controller-agent",
                    executor={"type": "omnigent", "config": {"harness": "openai-agents"}},
                    include_llm=False,
                    max_iterations=8 if scenario == "tools_cross_run" else None,
                    terminals={
                        "shell": {
                            "command": "bash",
                            "args": ["--noprofile", "--norc"],
                            "os_env": {
                                "type": "caller_process",
                                "cwd": "/workspace",
                                "sandbox": {"type": "none"},
                            },
                        }
                    }
                    if scenario == "tools_cross_run"
                    else None,
                ),
            )
            host_token = secrets.token_urlsafe(32)
            arm_external_host_credential(
                host_store._engine,
                workspace_id=runtime.physical_workspace_id,
                host_id="c" * 32,
                token=host_token,
                ttl_seconds=3600,
            )
            _private(exchange / "host-token", host_token)
            authentication = sessionmaker(applications["authenticator"], expire_on_commit=False)
            compatibility = load_runtime_compatibility_policy(
                case.root / "saas/upstream-baseline.json"
            )
            lifecycle = MembershipLifecycleService(authentication)
            integration = create_saas_http_integration(
                lifecycle=lifecycle,
                identities=IdentityManagementService(authentication),
                passwords=PasswordCredentialService(authentication),
                context_resolver=SqlAlchemyContextResolver(base.app_factory, compatibility),
                cookie_config=SaasCookieConfig(secure=True, trusted_origins=frozenset({ORIGIN})),
                runtime_store_adapter=OmnigentStoreAdapter("0.2.0"),
            )
            store = InteractiveConversationStore(
                delegate, fixture.service, permission_store=permissions, public_origin=ORIGIN
            )
            app = create_omnigent_saas_app(
                integration=integration,
                suppress_context_free_builtin_seed=True,
                **{**dependencies, "conversation_store": store},
                host_store=host_store,
                permission_store=permissions,
                project_store=projects,
            )
            app.state.production_interactive_conversation_store = store
            runtime_factory = ProductionInteractiveRuntimeFactory(
                product_revision=case.product_revision,
                image_digest=case.image_digest,
                app_sessions=base.app_factory,
                authenticator_sessions=authentication,
                compatibility=compatibility,
                conversation_store=delegate,
                permission_store=permissions,
            )
            credentials = ModelRunCredentialService(
                app_sessions=base.app_factory,
                authenticator_sessions=authentication,
                compatibility=compatibility,
            )
            with factory() as db:
                publication = json.loads(
                    db.scalars(sa.select(ModelPublicationVersionRecord.canonical_snapshot)).one()
                )
                draft = compile_stored_model_deployment(
                    db.get(ModelDeploymentVersionRecord, UUID(publication["deployment_id"]))
                )
                credential_name = db.get(
                    ModelCredentialVersionRecord, draft.credential_version_id
                ).credential_name
            actual = _real_litellm(publication, credential_name=credential_name)
            assert actual is not None
            before_calls = httpx.get(actual["upstream_url"] + "/evidence", trust_env=False).json()
            attestation_engine = sa.create_engine(
                actual["attestation_database_url"], hide_parameters=True
            )
            attestor = LiteLLMConfigurationAttestor(
                attestation_engine, salt_key=actual["salt_key"], expected_database="probe"
            )
            attestor.validate_authority()
            attestor.attest(draft=draft, credential_name=credential_name, expected_api_key=_KEY)
            _enable_budget(factory)
            with factory.begin() as db:
                configuration = db.get(ModelProviderConfigurationRecord, "deepseek")
                (
                    configuration.monthly_budget_microusd,
                    configuration.per_tenant_daily_token_limit,
                ) = 1_000_000, 100_000
            meter_root, control_root = tmp_path / "metering", tmp_path / "control"
            meter_root.mkdir()
            control_root.mkdir()
            meter_certificates, _ = _register_metering_certificate(
                factory, case.member.runner_id, case.member.connection_generation, meter_root
            )
            control_certificates = _certificates(control_root, runner_id=case.member.runner_id)
            control_certificates["runner"].private_key.chmod(0o600)
            meter_certificates["runner-0"].private_key.chmod(0o600)
            RunnerCertificateAuthority(
                factory, accepted_trust_bundle_versions=("test-v1",)
            ).activate_certificate(
                runner_id=case.member.runner_id,
                runner_connection_generation=case.member.connection_generation,
                purpose="runner_control",
                trust_bundle_version="test-v1",
                certificate_der=x509.load_pem_x509_certificate(
                    control_certificates["runner"].certificate.read_bytes()
                ).public_bytes(serialization.Encoding.DER),
            )
            gateway = PlatformModelGateway(
                tokens=None,
                configurations=None,
                pricing=None,
                budgets=ModelProviderBudgetAdmissionService(billing),
                run_credentials=credentials,
                run_inference=LiteLLMRunInference(
                    actual["proxy_url"],
                    actual["inference_key"],
                    (draft.alias,),
                    billing,
                    ("127.0.0.1",),
                ),
            )
            metering_server = MutualTlsBillingMeteringServer(
                BillingMeteringAuthority(metering),
                _server_context(meter_certificates["server"]),
                RunnerCertificateAuthority(metering, accepted_trust_bundle_versions=("test-v1",)),
                expected_host="localhost",
            )
            metering_thread = _ServerThread(metering_server)
            metering_thread.start()
            try:
                _serve_controller(
                    case,
                    workers,
                    app,
                    runtime_factory,
                    dependencies,
                    host_store,
                    control_certificates,
                    meter_certificates,
                    metering_server,
                    lifecycle,
                    runtime,
                    template,
                    delegate,
                    factory,
                    gateway,
                    tmp_path,
                    exchange,
                    monkeypatch,
                    scenario=scenario,
                )
                attestor.attest(
                    draft=draft, credential_name=credential_name, expected_api_key=_KEY
                )
                after_calls = httpx.get(
                    actual["upstream_url"] + "/evidence", trust_env=False
                ).json()
                assert len(after_calls["requests"]) - len(before_calls["requests"]) == (
                    4
                    if scenario == "tools_cross_run"
                    else 2
                    if scenario == "cancel_unknown_stream"
                    else 1
                )
                if scenario == "tools_cross_run":
                    assert [r["mode"] for r in after_calls["requests"]] == [
                        "tool",
                        "tool",
                        "text",
                        "text",
                    ]
                if scenario == "cancel_unknown_stream":
                    assert [r["mode"] for r in after_calls["requests"]] == [
                        "partial-stream",
                        "text",
                    ]
                    assert after_calls["requests"][0]["stream_started"]
            finally:
                metering_thread.close()
                attestation_engine.dispose()


def _serve_controller(
    case,
    workers,
    app,
    runtime_factory,
    dependencies,
    host_store,
    control_certificates,
    meter_certificates,
    metering_server,
    lifecycle,
    runtime,
    conversation,
    delegate,
    factory,
    gateway,
    tmp_path,
    exchange,
    monkeypatch,
    *,
    scenario="single",
):
    cancelling = scenario in {"cancel_before_admission", "cancel_unknown_stream"}
    initial_text = {
        "tools_cross_run": "P0_MANAGED_TOOL: write one unique marker",
        "cancel_unknown_stream": "P0_CANCEL_STREAM: cancel after the stream starts",
    }.get(scenario, "Build the requested page")
    control = MutualTlsRunnerControlServer(
        ProductionRunnerMachineAuthority(
            SchedulingControlPlane(workers["executor"]),
            ExecutionControlPlane(workers["executor"]),
            product_revision=case.product_revision,
            image_digest=case.image_digest,
        ),
        _control_server_context(control_certificates["server"]),
        DurableRunnerControlCertificateAuthorizer(
            RunnerCertificateAuthority(
                workers["executor"], accepted_trust_bundle_versions=("test-v1",)
            )
        ),
    )
    # The task-owned listener thread exposes both protocol servers on one event loop.
    ready_context, ready_ca = _readiness_tls(tmp_path)
    readiness = TlsRunnerControlReadinessServer(
        ready_context,
        lambda: assert_postgresql_runner_fleet_ready(
            workers["executor"].kw["bind"],
            product_revision=case.product_revision,
            official_schema_revision=case.schema_revision,
            adapter_contract_version="0.2.0",
        ),
    )
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    asyncio.run_coroutine_threadsafe(control.start(), loop).result(10)
    asyncio.run_coroutine_threadsafe(readiness.start(host="0.0.0.0"), loop).result(10)
    source = {
        **case.source,
        "OMNIGENT_SAAS_RUNNER_ID": str(case.member.runner_id),
        "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": str(case.member.connection_generation),
        "OMNIGENT_SAAS_RUNNER_CONNECTION_TOKEN_FILE": _private(
            tmp_path / "runner-token", case.connection_token
        ),
        "OMNIGENT_SAAS_RUNNER_AGENT_DATABASE_URL_FILE": _private(
            tmp_path / "runner-url", case.runner_engine.url.render_as_string(hide_password=False)
        ),
        "OMNIGENT_SAAS_RUNNER_CONTROL_HOST": "localhost",
        "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_NAME": "localhost",
        "OMNIGENT_SAAS_RUNNER_CONTROL_PORT": str(control.port),
        "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE": str(control_certificates["runner"].ca),
        "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_CERTIFICATE_FILE": str(
            control_certificates["runner"].certificate
        ),
        "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_KEY_FILE": str(
            control_certificates["runner"].private_key
        ),
        "OMNIGENT_SAAS_INTERACTIVE_METERING_URL": f"https://localhost:{metering_server.port}",
        "OMNIGENT_SAAS_INTERACTIVE_METERING_CA_FILE": str(meter_certificates["runner-0"].ca),
        "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_CERTIFICATE_FILE": str(
            meter_certificates["runner-0"].certificate
        ),
        "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_KEY_FILE": str(
            meter_certificates["runner-0"].private_key
        ),
        "OMNIGENT_SAAS_INTERACTIVE_RECOVERY_DIRECTORY": str(tmp_path / "controller-journal"),
        "OMNIGENT_SAAS_RUNNER_POLL_SECONDS": "0.1",
        "OMNIGENT_SAAS_RUNNER_HEARTBEAT_SECONDS": "5",
    }
    for name, value in {
        "OMNIGENT_SAAS_RUNNER_READINESS_HOST": "readiness.svc",
        "OMNIGENT_SAAS_RUNNER_READINESS_SERVER_NAME": "readiness.svc",
        "OMNIGENT_SAAS_RUNNER_READINESS_PORT": str(readiness.port),
        "OMNIGENT_SAAS_RUNNER_READINESS_CA_CERTIFICATE_FILE": str(ready_ca),
    }.items():
        monkeypatch.setenv(name, value)
    release = SimpleNamespace(
        product_revision=case.product_revision,
        image_digest=case.image_digest,
        public_origin=ORIGIN,
        adapter_contract_version="0.2.0",
    )
    adapter = None
    try:
        adapter = ProductionInteractiveControllerAdapter(config=release, source=source)
        adapter.bind_runtime(
            app=app,
            runtime=runtime_factory,
            official=SimpleNamespace(**{**dependencies, "host_store": host_store}),
            auth_provider=app.state.saas_http_integration.auth_provider,
        )
        certificate, key = _tls(tmp_path)
        (exchange / "ca.pem").write_bytes(certificate.read_bytes())
        issued = lifecycle.issue_auth_session(
            user_id=runtime.actor_id,
            authn_method="isolated_controller_acceptance",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        gateway_app = create_platform_model_gateway_app(gateway)
        observed, private_bearers = [], []
        request_waiting, admission_released = threading.Event(), threading.Event()
        if scenario != "single":

            @gateway_app.middleware("http")
            async def observe_model_request(request, call_next):
                bearer = request.headers.get("Authorization", "").removeprefix("Bearer ")
                body = await request.body()
                row = {
                    "bearer_sha256": sha256(bearer.encode()).hexdigest(),
                    "body_sha256": sha256(body).hexdigest(),
                    "call_id": request.headers.get("X-Omnigent-Gateway-Call"),
                }
                observed.append(row)
                private_bearers.append(bearer)
                if scenario == "tools_cross_run" and len(observed) == 2:
                    with factory() as db:
                        token = db.scalars(
                            sa.select(ModelRunTokenRecord).where(
                                ModelRunTokenRecord.token_hash == row["bearer_sha256"]
                            )
                        ).one()
                        assert token.expires_at - token.issued_at == timedelta(seconds=90)
                        expires_at = token.expires_at
                    await asyncio.sleep(
                        max(0, (expires_at - datetime.now(timezone.utc)).total_seconds()) + 0.1
                    )
                if scenario == "cancel_before_admission" and len(observed) == 1:
                    request_waiting.set()
                    assert await asyncio.to_thread(admission_released.wait, 40)
                response = await call_next(request)
                row["status"] = response.status_code
                if scenario == "cancel_unknown_stream" and len(observed) == 1:
                    assert response.status_code == 200
                    request_waiting.set()
                return response

        with (
            _listener(gateway_app, port=8090),
            _listener(app, port=443, certificate=certificate, key=key),
        ):
            pending_ready = exchange / "ready.pending"
            pending_ready.write_text(
                json.dumps(
                    {
                        "origin": ORIGIN,
                        "host_id": "c" * 32,
                        "workspace_id": runtime.physical_workspace_id,
                    }
                )
            )
            pending_ready.replace(exchange / "ready.json")

            async def connected():
                with bind_runtime_context(runtime):
                    return app.state.host_registry.get("c" * 32) is not None

            # The HTTP app's lifespan owns the controller task/event loop.
            app_loop = adapter._task.get_loop()
            _wait(
                lambda: asyncio.run_coroutine_threadsafe(connected(), app_loop).result(5),
                "owned Host WebSocket",
            )
            adapter.assert_production_ready()
            with httpx.Client(
                base_url=ORIGIN,
                trust_env=False,
                verify=ssl.create_default_context(cafile=str(certificate)),
                cookies={app.state.saas_http_integration.cookie_config.name: issued.token},
                timeout=60,
            ) as client:
                marker = conversation.inference_snapshot["managed_execution"]
                created = client.post(
                    "/v1/sessions",
                    json={
                        "agent_id": "b" * 32,
                        "project_id": conversation.project_id,
                        "host_type": "external",
                        "host_id": "c" * 32,
                        "workspace": "/workspace",
                        "model_override": marker["public_model_id"],
                        "inference_configuration_revision": (
                            f"managed-model:{marker['wire_api']}:{marker['generation']}:"
                            f"{marker['snapshot_sha256']}"
                        ),
                        "initial_items": [],
                    },
                    headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
                )
                assert created.status_code == 201, created.text
                with bind_runtime_context(runtime):
                    conversation = delegate.get_conversation(created.json()["id"])
                assert (
                    conversation.inference_snapshot["managed_launch"]["harness"] == "openai-agents"
                )
                result = client.post(
                    f"/v1/sessions/{conversation.id}/events",
                    json=_message(text=initial_text),
                    headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
                )
                assert result.status_code in {200, 202}, result.text
            assert (
                _queued_worker(workers["dispatcher"], workers["executor"])
                .dispatch_once()
                .published
                == 1
            )

            expected_runs = 1

            def released():
                if adapter._task.done():
                    error = adapter._task.exception()
                    chain, cursor = [], error
                    for _ in range(8):
                        if cursor is None:
                            break
                        chain.append(
                            {
                                "type": type(cursor).__name__,
                                "code": getattr(cursor, "code", None),
                                "frames": [
                                    {"file": f.filename, "line": f.lineno, "function": f.name}
                                    for f in traceback.extract_tb(cursor.__traceback__)
                                ],
                            }
                        )
                        cursor = cursor.__cause__ or cursor.__context__
                    with factory() as db:
                        run_states = [
                            {"id": str(r.id), "status": r.status}
                            for r in db.scalars(sa.select(RunRecord))
                        ]
                    (exchange / "failure.json").write_text(
                        json.dumps(
                            {
                                "errors": chain,
                                "runs": run_states,
                                "gateway_statuses": [r.get("status") for r in observed],
                                "journal": [
                                    {
                                        "phase": r.phase,
                                        "outcome": r.outcome,
                                        "process_stopped": r.process_stopped,
                                        "pending_gateway_references": len(
                                            list(r.grant.spool_directory.glob("*.pending.json"))
                                        ),
                                    }
                                    for r in adapter._journal.records()
                                ],
                            }
                        )
                    )
                    pytest.fail(
                        f"Controller exited: {type(error).__name__}, "
                        f"code={getattr(error, 'code', None)}"
                    )
                with factory() as db:
                    statuses = db.scalars(sa.select(RunRecord.status)).all()
                    forbidden = {"failed", "orphaned"}
                    if not cancelling:
                        forbidden.add("cancelled")
                    assert all(s not in forbidden for s in statuses), statuses
                    dispatches = db.scalars(sa.select(RunDispatchRecord.status)).all()
                    return len(dispatches) == expected_runs and all(
                        s == "released" for s in dispatches
                    )

            if cancelling:
                _wait(request_waiting.is_set, "actual Runner model request cancellation point")
                with factory() as db:
                    first_run = db.scalars(sa.select(RunRecord)).one()
                    assert first_run.status == "running"
                with bind_runtime_context(runtime):
                    first_runner = delegate.get_conversation(conversation.id).runner_id
                assert first_runner
                try:
                    with httpx.Client(
                        base_url=ORIGIN,
                        trust_env=False,
                        verify=ssl.create_default_context(cafile=str(certificate)),
                        cookies={app.state.saas_http_integration.cookie_config.name: issued.token},
                        timeout=60,
                    ) as client:
                        for _ in range(2):
                            interrupted = client.post(
                                f"/v1/sessions/{conversation.id}/events",
                                json={"type": "interrupt", "data": {}},
                                headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
                            )
                            assert interrupted.status_code == 202, interrupted.text
                    with factory() as db:
                        assert db.get(RunRecord, first_run.id).status == "cancelling"
                        assert (
                            db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord))
                            == 0
                        )
                        holds = db.scalars(
                            sa.select(ModelProviderBudgetReservationRecord).where(
                                ModelProviderBudgetReservationRecord.purpose == "tenant_run"
                            )
                        ).all()
                        assert len(holds) == (1 if scenario == "cancel_unknown_stream" else 0)
                        if holds:
                            assert holds[0].status in {"in_flight", "uncertain"}
                    _wait(
                        lambda: adapter._journal.read(first_run.id).process_stopped,
                        "automatic cancellation and exact physical Host stop acknowledgement",
                        timeout=35,
                    )
                finally:
                    admission_released.set()
            _wait(released, "actual controller Run completion", timeout=150)
            if cancelling:
                cancelled = adapter._journal.read(first_run.id)
                assert cancelled.phase == "terminal" and cancelled.outcome == "cancelled"
                assert cancelled.process_stopped
                assert [r["status"] for r in observed] == (
                    [200] if scenario == "cancel_unknown_stream" else [403]
                )
                if scenario == "cancel_unknown_stream":
                    assert len(list(cancelled.grant.spool_directory.glob("*.pending.json"))) == 1
                old_bearer = private_bearers[0]

                def deny_cancelled_bearer():
                    denied = httpx.post(
                        "http://127.0.0.1:8090/v1/chat/completions",
                        trust_env=False,
                        headers={"Authorization": "Bearer " + old_bearer},
                        json=_document(conversation.model_override, limit=32),
                    )
                    assert denied.status_code == 403
                    assert denied.json()["error"]["code"] == (
                        "platform_model_run_authority_unavailable"
                    )

                deny_cancelled_bearer()
                with httpx.Client(
                    base_url=ORIGIN,
                    trust_env=False,
                    verify=ssl.create_default_context(cafile=str(certificate)),
                    cookies={app.state.saas_http_integration.cookie_config.name: issued.token},
                    timeout=60,
                ) as client:
                    replay = client.post(
                        f"/v1/sessions/{conversation.id}/events",
                        json=_message(text=initial_text),
                        headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
                    )
                    assert replay.status_code == 202
                    assert replay.json()["run_id"] == str(first_run.id)
                    assert (
                        replay.json()["run_status"] == "cancelled" and not replay.json()["queued"]
                    )
                    retried = client.post(
                        f"/v1/sessions/{conversation.id}/events",
                        json={"type": "retry_session", "data": {}},
                        headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
                    )
                    assert retried.status_code == 202 and not retried.json()["queued"]
                    resumed = client.post(
                        f"/v1/sessions/{conversation.id}/events",
                        json=_message("d" * 32, "Start a new turn after cancellation"),
                        headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
                    )
                    assert resumed.status_code == 202, resumed.text
                assert (
                    _queued_worker(workers["dispatcher"], workers["executor"])
                    .dispatch_once()
                    .published
                    == 1
                )
                expected_runs = 2
                _wait(
                    released, "fresh input on a replacement Runner after cancellation", timeout=150
                )
                with bind_runtime_context(runtime):
                    assert delegate.get_conversation(conversation.id).runner_id != first_runner
                deny_cancelled_bearer()
            if scenario == "tools_cross_run":
                with factory() as db:
                    first_run = db.scalars(sa.select(RunRecord)).one()
                with bind_runtime_context(runtime):
                    first_runner = delegate.get_conversation(conversation.id).runner_id
                assert first_runner
                assert [r["status"] for r in observed] == [200, 401, 200, 200]
                assert observed[1]["call_id"] == observed[2]["call_id"]
                assert observed[1]["body_sha256"] == observed[2]["body_sha256"]
                assert observed[1]["bearer_sha256"] != observed[2]["bearer_sha256"]
                old_bearer = private_bearers[-1]

                def deny_terminal_bearer():
                    denied = httpx.post(
                        "http://127.0.0.1:8090/v1/chat/completions",
                        trust_env=False,
                        headers={"Authorization": "Bearer " + old_bearer},
                        json=_document(conversation.model_override, limit=32),
                    )
                    assert (
                        denied.status_code == 403
                        and denied.json()["error"]["code"]
                        == "platform_model_run_authority_unavailable"
                    )

                deny_terminal_bearer()
                with httpx.Client(
                    base_url=ORIGIN,
                    trust_env=False,
                    verify=ssl.create_default_context(cafile=str(certificate)),
                    cookies={app.state.saas_http_integration.cookie_config.name: issued.token},
                    timeout=60,
                ) as client:
                    for _ in range(2):
                        result = client.post(
                            f"/v1/sessions/{conversation.id}/events",
                            json=_message("d" * 32, "Follow up without writing the marker again"),
                            headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
                        )
                        assert result.status_code in {200, 202}, result.text
                assert (
                    _queued_worker(workers["dispatcher"], workers["executor"])
                    .dispatch_once()
                    .published
                    == 1
                )
                expected_runs = 2
                _wait(released, "cross-Run reuse and credential rollover", timeout=150)
                with bind_runtime_context(runtime):
                    assert delegate.get_conversation(conversation.id).runner_id == first_runner
                deny_terminal_bearer()
            with factory() as db:
                runs = db.scalars(sa.select(RunRecord)).all()
                assert len(runs) == expected_runs
                assert {r.status for r in runs} == (
                    {"cancelled", "succeeded"} if cancelling else {"succeeded"}
                )
                run = next(r for r in runs if scenario == "single" or r.id != first_run.id)
                assert db.get(RunnerRegistrationRecord, case.member.runner_id).active_leases == 0
                calls = 4 if scenario == "tools_cross_run" else 1
                for model, count in (
                    (TaskRecord, expected_runs),
                    (
                        ModelRunTokenRecord,
                        3 if scenario == "tools_cross_run" else 2 if cancelling else 1,
                    ),
                    (UsageEventRecord, 2 * calls),
                    (BillingMeteringReceiptRecord, 2 * calls),
                ):
                    assert db.scalar(sa.select(sa.func.count()).select_from(model)) == count
                assert (
                    db.scalar(sa.select(sa.func.sum(UsageEventRecord.customer_charge_minor)))
                    == 2 * calls
                )
                budgets = db.scalars(
                    sa.select(ModelProviderBudgetReservationRecord).where(
                        ModelProviderBudgetReservationRecord.purpose == "tenant_run"
                    )
                ).all()
                uncertain = [b for b in budgets if b.status == "uncertain"]
                settled = [b for b in budgets if b.status == "settled"]
                assert len(settled) == calls and all(b.settled_tokens == 22 for b in settled)
                if scenario == "cancel_unknown_stream":
                    assert len(budgets) == 2 and len(uncertain) == 1
                    hold = uncertain[0]
                    assert hold.run_id == first_run.id and hold.admitted_microusd > 0
                    assert hold.admitted_tokens > 0
                    assert hold.settled_tokens == hold.settled_microusd == 0
                    assert hold.released_tokens == hold.released_microusd == 0
                    assert set(
                        db.scalars(
                            sa.select(ModelGatewayEvidenceRecord.phase).where(
                                ModelGatewayEvidenceRecord.reservation_id == hold.id
                            )
                        )
                    ) == {"request", "in_flight", "uncertain"}
                else:
                    assert len(budgets) == calls
                if scenario == "tools_cross_run":
                    tokens = db.scalars(sa.select(ModelRunTokenRecord)).all()
                    assert (
                        len({t.token_hash for t in tokens}) == 3
                        and len({t.run_id for t in tokens}) == 2
                    )
                    assert sorted(t.generation for t in tokens) == [0, 0, 1]
                    assert all(t.expires_at - t.issued_at == timedelta(seconds=90) for t in tokens)
                    assert [r["status"] for r in observed] == [200, 401, 200, 200, 403, 200, 403]
                if cancelling:
                    assert [r["status"] for r in observed] == (
                        [200, 403, 200, 403]
                        if scenario == "cancel_unknown_stream"
                        else [403, 403, 200, 403]
                    )
                    assert len({r["bearer_sha256"] for r in observed}) == 2
                    assert db.get(RunRecord, first_run.id).status == "cancelled"
            if scenario == "cancel_unknown_stream":
                asyncio.run_coroutine_threadsafe(
                    adapter._executor.reconcile_physical_gc(limit=10), app_loop
                ).result(20)
                assert (
                    gateway._budgets.recover_expired(now=hold.expires_at + timedelta(days=1)) == ()
                )
                assert len(list(cancelled.grant.spool_directory.glob("*.pending.json"))) == 1
                with factory() as db:
                    assert (
                        db.get(ModelProviderBudgetReservationRecord, hold.id).status == "uncertain"
                    )
                    assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 2
                    monthly = db.get(
                        ModelProviderMonthlyBudgetRecord, (hold.provider_id, hold.period_start)
                    )
                    daily = db.get(
                        ModelProviderTenantDailyUsageRecord,
                        (hold.tenant_id, hold.provider_id, hold.usage_date),
                    )
                    assert monthly.reserved_microusd == hold.admitted_microusd
                    assert daily.reserved_tokens == hold.admitted_tokens
                    assert daily.settled_tokens == 22
            with bind_runtime_context(runtime):
                assert "OK" in str(delegate.list_items(conversation.id, limit=100))
            record = adapter._journal.read(run.id)
            assert record.phase == "terminal" and record.outcome == "succeeded"
            assert asyncio.run_coroutine_threadsafe(
                adapter._executor._driver.stop(record), app_loop
            ).result(20)
            adapter.assert_production_ready()
            (exchange / "result.json").write_text(
                json.dumps(
                    {
                        "passed": True,
                        "production_factory": True,
                        "controller_adapter": True,
                        "physical_host": True,
                        "actual_litellm": True,
                        "production_pki": False,
                        "scenario": scenario,
                        "test_model_token_ttl_seconds": 90
                        if scenario == "tools_cross_run"
                        else 28800,
                        "task_count": expected_runs,
                        "usage_facts": 2 * calls,
                        "settled_tokens": 22 * calls,
                        "supplier_calls": calls + (scenario == "cancel_unknown_stream"),
                        "controlled_expiry_restored": scenario == "tools_cross_run",
                        "gateway_request_statuses": [r["status"] for r in observed],
                        "same_runner_cross_run": scenario == "tools_cross_run",
                        "public_interrupt_accepted": cancelling,
                        "cancelled_message_replay_did_not_restart": cancelling,
                        "replacement_runner_after_cancel": cancelling,
                        "unknown_usage_hold_and_reference_retained": scenario
                        == "cancel_unknown_stream",
                        "pending_provider_budget": {
                            "status": "uncertain",
                            "admitted_microusd": hold.admitted_microusd,
                            "admitted_tokens": hold.admitted_tokens,
                            "not_auto_expired": True,
                        }
                        if scenario == "cancel_unknown_stream"
                        else None,
                        "host_stop_acknowledged": True,
                        "manual_run_heartbeat": False,
                    }
                )
            )
    finally:
        if adapter is not None:
            adapter.close()
        asyncio.run_coroutine_threadsafe(control.aclose(), loop).result(10)
        asyncio.run_coroutine_threadsafe(readiness.aclose(), loop).result(10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)
        loop.close()


def _delegate(case, tmp_path):
    command = json.loads(os.environ["OMNIGENT_SAAS_TEST_CONTROLLER_BRIDGE"])
    path = tmp_path / "controller-case.json"
    _private(
        path,
        json.dumps(
            {
                "database_url": case.engine.url.render_as_string(hide_password=False),
                "runner_url": case.runner_engine.url.render_as_string(hide_password=False),
                "member": asdict(case.member),
                "source": case.source,
                "product_revision": case.product_revision,
                "image_digest": case.image_digest,
                "pool_id": str(case.pool_id),
                "placement_id": str(case.placement_id),
                "schema_revision": case.schema_revision,
                "connection_token": case.connection_token,
                "scenario": os.environ.get("OMNIGENT_SAAS_TEST_CONTROLLER_SCENARIO", "single"),
            },
            default=str,
        ),
    )
    try:
        subprocess.run([*command, str(path)], check=True, timeout=420)
    finally:
        path.unlink()


def test_actual_controller_factory_host_litellm_and_pg18_billing(
    tmp_path, db_uri, monkeypatch, request
):
    private = os.environ.get("OMNIGENT_SAAS_TEST_CONTROLLER_CASE_FILE")
    if private is not None:
        document = json.loads(Path(private).read_text())

        def engine(value):
            return sa.create_engine(
                sa.engine.make_url(value)
                .set(host="postgresql.lab", port=5432)
                .update_query_dict(
                    {"sslmode": "verify-full", "sslrootcert": "/runtime/postgresql-ca.crt"}
                )
            )

        case = SimpleNamespace(
            **{
                k: document[k]
                for k in (
                    "source",
                    "product_revision",
                    "image_digest",
                    "schema_revision",
                    "connection_token",
                )
            }
        )
        case.scenario = document.get("scenario", "single")
        case.engine, case.runner_engine = (
            engine(document["database_url"]),
            engine(document["runner_url"]),
        )
        case.member = SimpleNamespace(**document["member"])
        case.member.runner_id = UUID(case.member.runner_id)
        case.pool_id, case.placement_id, case.root = (
            UUID(document["pool_id"]),
            UUID(document["placement_id"]),
            Path.cwd(),
        )
        try:
            _physical_controller(case, db_uri, tmp_path, monkeypatch)
        finally:
            case.engine.dispose()
            case.runner_engine.dispose()
    elif "OMNIGENT_SAAS_TEST_CONTROLLER_BRIDGE" in os.environ:
        _signed_fleet(
            request.getfixturevalue("isolated_postgres_url"),
            tmp_path,
            runtime_probe=lambda case: _delegate(case, tmp_path),
        )
    else:
        pytest.skip("requires the task-owned signed Fleet/PG18, actual LiteLLM and Host harness")
