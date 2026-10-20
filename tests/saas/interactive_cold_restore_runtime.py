"""Rebuild an existing isolated controller without creating SQL or model identities."""

from __future__ import annotations

import asyncio
import json
import os
import ssl
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from tests.saas.interactive_cold_restore import load_cold_checkpoint


def run_cold_controller(root: Path, monkeypatch) -> None:
    from omnigent.server.managed_hosts import parse_sandbox_config
    from saas.control_plane import ExecutionRevisionSet
    from saas.control_plane.interactive_execution import RuntimeSessionRunAdmission
    from saas.production.interactive_recovery import InteractiveRecoveryJournal
    from tests.saas import test_interactive_controller_factory_process as physical

    document = load_cold_checkpoint(root)
    state = document["payload"]
    if state.get("must_not_reseed") is not True or state.get("root") != str(root):
        raise ValueError("invalid cold fixture checkpoint")
    for name, value in state["runtime_environment"].items():
        monkeypatch.setenv(name, value)
    cluster = dict(state["cluster"])
    cluster["bind_host"] = os.environ["POD_IP"]
    physical.ORIGIN = cluster["sandbox"]["server_url"].rstrip("/")
    engines = []

    def engine(url):
        result = sa.create_engine(url, hide_parameters=True)
        engines.append(result)
        return result

    frozen_case = state["case"]
    case = SimpleNamespace(
        **{
            key: frozen_case[key]
            for key in (
                "source",
                "product_revision",
                "image_digest",
                "schema_revision",
                "connection_token",
            )
        },
        member=SimpleNamespace(**frozen_case["member"]),
        pool_id=UUID(frozen_case["pool_id"]),
        placement_id=UUID(frozen_case["placement_id"]),
        root=Path.cwd(),
        engine=engine(frozen_case["database_url"]),
        runner_engine=engine(frozen_case["runner_url"]),
    )
    case.member.runner_id = UUID(case.member.runner_id)
    journal = InteractiveRecoveryJournal(root / "controller-journal")
    try:
        old = journal.read(UUID(state["run_id"]))
        runtime = old.runtime
    finally:
        journal.close()
    applications = {key: engine(url) for key, url in state["application_urls"].items()}
    workers = {
        key: sessionmaker(engine(url), expire_on_commit=False)
        for key, url in state["worker_urls"].items()
    }
    factory = sessionmaker(case.engine, expire_on_commit=False)
    app_sessions = sessionmaker(applications["app"], expire_on_commit=False)
    authentication = sessionmaker(applications["authenticator"], expire_on_commit=False)
    billing = sessionmaker(engine(state["billing_url"]), expire_on_commit=False)
    metering = sessionmaker(engine(state["metering_url"]), expire_on_commit=False)
    compatibility = physical.load_runtime_compatibility_policy(
        case.root / "saas/upstream-baseline.json"
    )
    dependencies = physical._official_dependencies(state["official_database_url"], root)
    permissions = physical.SqlAlchemyPermissionStore(state["official_database_url"])
    projects = physical.SqlAlchemyProjectStore(state["official_database_url"])
    host_store = physical.HostStore(state["official_database_url"])
    delegate = dependencies["conversation_store"]
    with physical.OmnigentStoreAdapter("0.2.0").bind(runtime):
        conversation = delegate.get_conversation(old.scope.official_session_id)
    if conversation is None:
        raise ValueError("original cold fixture conversation is missing")
    lifecycle = physical.MembershipLifecycleService(authentication)
    integration = physical.create_saas_http_integration(
        lifecycle=lifecycle,
        identities=physical.IdentityManagementService(authentication),
        passwords=physical.PasswordCredentialService(authentication),
        context_resolver=physical.SqlAlchemyContextResolver(app_sessions, compatibility),
        cookie_config=physical.SaasCookieConfig(
            secure=True, trusted_origins=frozenset({physical.ORIGIN})
        ),
        runtime_store_adapter=physical.OmnigentStoreAdapter("0.2.0"),
    )
    service = RuntimeSessionRunAdmission(
        app_sessions,
        revisions=ExecutionRevisionSet(
            case.product_revision, runtime.source_revision, case.schema_revision, "0.2.0"
        ),
    )
    store = physical.InteractiveConversationStore(
        delegate,
        service,
        permission_store=permissions,
        public_origin=physical.ORIGIN,
        runtime_enabled=True,
    )
    app = physical.create_omnigent_saas_app(
        integration=integration,
        suppress_context_free_builtin_seed=True,
        **{**dependencies, "conversation_store": store},
        host_store=host_store,
        permission_store=permissions,
        project_store=projects,
        sandbox_config=parse_sandbox_config(cluster["sandbox"]),
    )
    app.state.production_interactive_conversation_store = store
    runtime_factory = physical.ProductionInteractiveRuntimeFactory(
        product_revision=case.product_revision,
        image_digest=case.image_digest,
        app_sessions=app_sessions,
        authenticator_sessions=authentication,
        compatibility=compatibility,
        conversation_store=delegate,
        permission_store=permissions,
    )
    credentials = physical.ModelRunCredentialService(
        app_sessions=app_sessions,
        authenticator_sessions=authentication,
        compatibility=compatibility,
    )
    actual = state["actual_litellm"]
    with factory() as database:
        publication = json.loads(
            database.scalars(
                sa.select(physical.ModelPublicationVersionRecord.canonical_snapshot)
            ).one()
        )
        draft = physical.compile_stored_model_deployment(
            database.get(physical.ModelDeploymentVersionRecord, UUID(publication["deployment_id"]))
        )
        credential_name = database.get(
            physical.ModelCredentialVersionRecord, draft.credential_version_id
        ).credential_name
    attestor = physical.LiteLLMConfigurationAttestor(
        engine(actual["attestation_database_url"]),
        salt_key=actual["salt_key"],
        expected_database="probe",
    )
    attestor.validate_authority()
    attestor.attest(
        draft=draft, credential_name=credential_name, expected_api_key=actual["provider_key"]
    )
    gateway = physical.PlatformModelGateway(
        tokens=None,
        configurations=None,
        pricing=None,
        budgets=physical.ModelProviderBudgetAdmissionService(billing),
        run_credentials=credentials,
        run_inference=physical.LiteLLMRunInference(
            actual["proxy_url"], actual["inference_key"], (draft.alias,), billing, ("127.0.0.1",)
        ),
    )
    certificates = {
        group: {
            key: SimpleNamespace(**{field: Path(value) for field, value in paths.items()})
            for key, paths in values.items()
        }
        for group, values in state["certificates"].items()
    }
    authority = physical.BillingMeteringAuthority(metering)
    metering_server = physical.MutualTlsBillingMeteringServer(
        authority,
        physical._server_context(certificates["metering"]["server"]),
        physical.RunnerCertificateAuthority(metering, accepted_trust_bundle_versions=("test-v1",)),
        expected_host="localhost",
    )
    start = metering_server.start

    async def original_metering_port():
        await start(port=urlsplit(state["source"]["OMNIGENT_SAAS_INTERACTIVE_METERING_URL"]).port)

    metering_server.start = original_metering_port
    ready = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ready.minimum_version = ready.maximum_version = ssl.TLSVersion.TLSv1_3
    ready.load_cert_chain(root / "readiness.pem", root / "readiness-key.pem")
    metering_thread = physical._ServerThread(metering_server)
    metering_thread.start()
    try:
        physical._serve_controller(
            case,
            workers,
            app,
            runtime_factory,
            dependencies,
            host_store,
            certificates["control"],
            certificates["metering"],
            metering_server,
            lifecycle,
            runtime,
            conversation,
            delegate,
            factory,
            gateway,
            root,
            Path("/exchange"),
            monkeypatch,
            delivery=physical._MeteringDeliveryGate(authority, paused=False),
            control_ports=(
                int(state["source"]["OMNIGENT_SAAS_RUNNER_CONTROL_PORT"]),
                int(state["runtime_environment"]["OMNIGENT_SAAS_RUNNER_READINESS_PORT"]),
            ),
            ready_material=(ready, root / "readiness.pem"),
            cluster=cluster,
            cold_restore=state,
        )
    finally:
        metering_thread.close()
        for value in engines:
            value.dispose()


def assert_restored_dormant(
    *,
    state,
    adapter,
    app,
    app_loop,
    runtime,
    conversation,
    delegate,
    factory,
    workers,
    issued,
    certificate,
    exchange,
    observed,
):
    import httpx

    from saas.production.interactive_model_channel import channel_url
    from tests.saas import test_interactive_controller_factory_process as physical

    def database_state():
        with factory() as database:
            return {
                "runs": {
                    str(row.id): row.status
                    for row in database.scalars(sa.select(physical.RunRecord))
                },
                "tasks": database.scalar(
                    sa.select(sa.func.count()).select_from(physical.TaskRecord)
                ),
                "usage": database.scalar(
                    sa.select(sa.func.count()).select_from(physical.UsageEventRecord)
                ),
                "receipts": database.scalar(
                    sa.select(sa.func.count()).select_from(physical.BillingMeteringReceiptRecord)
                ),
                "old_usage": database.scalar(
                    sa.select(sa.func.count())
                    .select_from(physical.UsageEventRecord)
                    .where(physical.UsageEventRecord.run_id == UUID(state["run_id"]))
                ),
            }

    old = adapter._journal.read(UUID(state["run_id"]))
    assert physical.managed_suspension_proof_sha256(old) == state["old_suspension_sha256"]
    assert physical.physical_recovery_proof_sha256(old) == state["old_physical_stop_sha256"]
    before = database_state()
    assert before == {
        "runs": {state["run_id"]: "succeeded"},
        "tasks": 1,
        "usage": 6,
        "receipts": 6,
        "old_usage": 6,
    }
    adapter.assert_production_ready()
    with physical.OmnigentStoreAdapter("0.2.0").bind(runtime):
        assert delegate.get_conversation(conversation.id).id == old.scope.official_session_id
    context = ssl.create_default_context(cafile=str(certificate))
    cookies = {app.state.saas_http_integration.cookie_config.name: issued.token}
    with httpx.Client(
        base_url=physical.ORIGIN, trust_env=False, verify=context, cookies=cookies, timeout=60
    ) as client:
        for _ in range(2):
            response = client.post(
                f"/v1/sessions/{conversation.id}/events",
                json=physical._message(
                    "9" * 32, "Use retained files; do not write the marker again"
                ),
                headers={"Origin": physical.ORIGIN, "X-CSRF-Token": issued.csrf_token},
            )
            assert response.status_code in {200, 202}, response.text
    assert (
        physical._queued_worker(workers["dispatcher"], workers["executor"])
        .dispatch_once()
        .published
        == 1
    )

    def released():
        assert not adapter._task.done(), "cold controller stopped"
        value = database_state()
        assert set(value["runs"].values()) <= {
            "queued",
            "leased",
            "starting",
            "running",
            "succeeded",
        }, value["runs"]
        with factory() as database:
            dispatches = database.scalars(sa.select(physical.RunDispatchRecord.status)).all()
        return len(dispatches) == 2 and all(value == "released" for value in dispatches)

    physical._wait(
        released, "cold restored controller completes exactly one new input", timeout=180
    )
    after = database_state()
    assert len(after["runs"]) == 2 and set(after["runs"].values()) == {"succeeded"}
    assert (after["tasks"], after["usage"], after["receipts"], after["old_usage"]) == (2, 8, 8, 6)
    (new_id,) = set(after["runs"]) - {state["run_id"]}
    current = adapter._journal.read(UUID(new_id))
    assert current.managed_predecessor_run_id == old.run_id and current.managed_resume
    assert current.managed_resources.workload_uid == old.managed_resources.workload_uid
    assert current.managed_resources.token_secret_uid != old.managed_resources.token_secret_uid
    assert current.managed_creation.pod_uid != old.managed_creation.pod_uid
    assert current.official_runner_id != old.official_runner_id
    assert current.channel_value != old.channel_value
    with httpx.Client(
        base_url=physical.ORIGIN, trust_env=False, verify=context, cookies=cookies, timeout=30
    ) as client:
        environment = client.get(f"/v1/sessions/{conversation.id}/resources/environments/default")
        assert environment.status_code == 200
        assert environment.json()["metadata"]["root"] == "/home/omnigent/workspace"
        response = client.get(
            f"/v1/sessions/{conversation.id}/resources/environments/default/filesystem/litellm-pvc-once.txt"
        )
        assert response.status_code == 200, response.text
        file = response.json()
        assert file["object"] == "session.environment.filesystem.file_content"
        assert file["encoding"] == "utf-8" and not file["truncated"]
        content = file["content"]
        assert content == "LITELLM_PVC_ONCE\n"
    with httpx.Client(trust_env=False, verify=context, timeout=20) as client:
        denied = client.post(
            channel_url(physical.ORIGIN, old.scope.session_id) + "/responses",
            headers={"Authorization": "Bearer " + old.channel_value},
            json={},
        )
        assert denied.status_code == 403
    denied = httpx.post(
        "http://127.0.0.1:8090/v1/chat/completions",
        trust_env=False,
        headers={"Authorization": "Bearer " + state["old_bearer"]},
        json=physical._document(conversation.model_override, limit=32),
    )
    assert denied.status_code == 403
    assert [value["status"] for value in observed] == [200, 403]
    assert (
        physical.managed_suspension_proof_sha256(adapter._journal.read(old.run_id))
        == state["old_suspension_sha256"]
    )
    reaper = app.state.managed_sandbox_reaper

    def retired():
        import time

        asyncio.run_coroutine_threadsafe(
            reaper.sweep_once(now=int(time.time()) + 8 * 86400), app_loop
        ).result(45)
        restored = adapter._journal.read(current.run_id)
        return restored.managed_termination is not None and restored.managed_termination.complete

    physical._wait(retired, "product retires cold resumed generation", timeout=150)
    stopped = adapter._journal.read(current.run_id)
    assert stopped.process_stopped and stopped.managed_termination.complete
    assert (
        physical.physical_recovery_proof_sha256(adapter._journal.read(old.run_id))
        == state["old_physical_stop_sha256"]
    )
    with factory() as database:
        for identifier in (old.run_id, current.run_id):
            run = database.get(physical.RunRecord, identifier)
            assert (
                database.get(physical.RunDispatchRecord, identifier).physical_recovery_fence
                == run.fence_token
            )
        tokens = database.scalar(sa.select(sa.func.sum(physical.UsageEventRecord.quantity)))
        assert tokens == 88
    (exchange / "result.json").write_text(
        json.dumps(
            {
                "passed": True,
                "cold_controller_process": True,
                "existing_database_identities_reused": True,
                "original_credentials_reused": True,
                "run_count": 2,
                "usage_facts": 8,
                "receipts": 8,
                "old_usage_facts": 6,
                "settled_tokens": int(tokens),
                "workspace_sha256": physical.sha256(content.encode()).hexdigest(),
                "workspace_lines": 1,
                "old_credentials_rejected": True,
                "old_input_not_replayed": True,
                "final_complete_retirement_by_product": True,
                "old_run_id": str(old.run_id),
                "new_run_id": str(current.run_id),
                "old_resources": state["old_resources"],
                "new_resources": physical.asdict(current.managed_resources),
                "new_creation": physical.asdict(current.managed_creation),
                "termination": physical.asdict(stopped.managed_termination),
                "production_ready": False,
                "actual_pod_replacement_verified_by_outer_driver": False,
            }
        )
    )
