from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import sessionmaker

from omnigent.server.auth import LEVEL_OWNER
from omnigent.server.schemas import SessionEventInput
from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore
from omnigent.stores.project_store.sqlalchemy_store import SqlAlchemyProjectStore
from saas.compatibility import bind_runtime_context
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord, TaskRecord
from saas.control_plane.model_routing_models import ModelRunTokenRecord
from saas.control_plane.resolver import load_runtime_compatibility_policy
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import RunDispatchRecord, RunnerRegistrationRecord
from saas.production.interactive_runtime import ProductionInteractiveRuntimeFactory
from saas.production.model_run_credentials import ModelRunCredentialService
from saas.production.runner_control import (
    DurableRunnerControlCertificateAuthorizer,
    MutualTlsRunnerControlClient,
    MutualTlsRunnerControlServer,
    ProductionRunnerMachineAuthority,
    RunnerControlError,
)
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenError
from tests.saas.test_execution_control_plane import _execution_fixture
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_http import _message, _queued_worker, _scheduling
from tests.saas.test_interactive_execution_postgresql import _interactive_postgresql_case
from tests.saas.test_official_http_integration import _official_dependencies
from tests.saas.test_production_runner_control import (
    _certificates,
    _client_context,
    _server_context,
)
from tests.saas.test_production_runner_database_fleet_postgresql import (
    test_pg18_signed_exact_two_runner_fleet_lifecycle_and_sticky_poison as _signed_fleet,
)


@contextmanager
def _application_logins(case):
    engines, roles = {}, []
    database = case.engine.dialect.identifier_preparer.quote(case.engine.url.database)
    try:
        for purpose in ("app", "authenticator"):
            login, password = f"factory_{purpose}_{uuid4().hex[:12]}", uuid4().hex
            with case.engine.begin() as connection:
                connection.exec_driver_sql(
                    f"CREATE ROLE {login} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS "
                    "NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT CONNECTION LIMIT 8"
                )
                connection.exec_driver_sql(
                    f"GRANT saas_{purpose} TO {login} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
                )
                connection.exec_driver_sql(f"GRANT CONNECT ON DATABASE {database} TO {login}")
            roles.append(login)
            engine = sa.create_engine(case.engine.url.set(username=login, password=password))
            engines[purpose] = engine
            with engine.connect() as connection:
                assert connection.exec_driver_sql(
                    "SELECT current_user=session_user,rolsuper,rolbypassrls "
                    "FROM pg_roles WHERE rolname=current_user"
                ).one() == (True, False, False)
                assert connection.exec_driver_sql(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
                ).scalar_one()
                assert not connection.exec_driver_sql(
                    "SELECT has_table_privilege("
                    "current_user,'saas_customer_ledger_entries','INSERT')"
                ).scalar_one()
        yield engines
    finally:
        for engine in engines.values():
            engine.dispose()
        with case.engine.begin() as connection:
            for role in reversed(roles):
                connection.exec_driver_sql(f"DROP OWNED BY {role}")
                connection.exec_driver_sql(f"DROP ROLE {role}")


def _factory_run(case, *, db_uri, tmp_path, monkeypatch, inference_probe=None):
    with _application_logins(case) as applications, _worker_logins(case) as workers:
        with case.engine.connect() as connection:
            before = connection.exec_driver_sql(
                "SELECT oid,relname FROM pg_class WHERE relnamespace='public'::regnamespace "
                "ORDER BY oid"
            ).all()
        factory, _, scope, request = _execution_fixture(case.engine)
        with case.engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT oid,relname FROM pg_class WHERE relnamespace='public'::regnamespace "
                    "ORDER BY oid"
                ).all()
                == before
            )
        base = SimpleNamespace(
            engine=case.engine,
            factory=factory,
            scope=scope,
            context=request,
            app=applications["app"],
            app_factory=sessionmaker(applications["app"], expire_on_commit=False),
        )
        manifest = json.loads((case.root / "saas/upstream-baseline.json").read_text())
        assert manifest["upstream_revision"] != case.product_revision
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
        if inference_probe is not None:
            from tests.saas.test_gateway_machine_metering import _customer_prices

            _customer_prices(factory, actor=runtime.actor_id, tenant=runtime.tenant_id)
        dependencies = _official_dependencies(db_uri, tmp_path)
        conversations = dependencies["conversation_store"]
        permissions, projects = SqlAlchemyPermissionStore(db_uri), SqlAlchemyProjectStore(db_uri)
        template = fixture.conversation
        with bind_runtime_context(runtime):
            projects.create(template.project_id, "Factory acceptance", runtime.runtime_user_key)
            fixture.conversation = conversations.create_conversation(
                conversation_id=template.id,
                agent_id=template.agent_id,
                host_id=template.host_id,
                project_id=template.project_id,
                workspace=template.workspace,
                model_override=template.model_override,
                inference_snapshot=template.inference_snapshot,
            )
            permissions.grant(runtime.runtime_user_key, template.id, LEVEL_OWNER)
        _scheduling(factory, runtime, runtime.project_id, pool_id=case.pool_id)
        with bind_runtime_context(runtime):
            admitted = fixture.service.dispatch(
                runtime,
                fixture.conversation,
                SessionEventInput.model_validate(_message()),
                created_by=runtime.runtime_user_key,
            )
        result = _queued_worker(workers["dispatcher"], workers["executor"]).dispatch_once()
        with factory() as database:
            errors = database.scalars(
                sa.select(ControlPlaneOutboxEvent.last_error_code).where(
                    ControlPlaneOutboxEvent.aggregate_type == "run"
                )
            ).all()
        assert result.published == 1, (result, errors)
        certificates = _certificates(tmp_path, runner_id=case.member.runner_id)
        certificate_authority = RunnerCertificateAuthority(
            factory, accepted_trust_bundle_versions=("test-v1",)
        )
        certificate_authority.activate_certificate(
            runner_id=case.member.runner_id,
            runner_connection_generation=case.member.connection_generation,
            purpose="runner_control",
            trust_bundle_version="test-v1",
            certificate_der=x509.load_pem_x509_certificate(
                certificates["runner"].certificate.read_bytes()
            ).public_bytes(serialization.Encoding.DER),
        )

        async def run():
            server = MutualTlsRunnerControlServer(
                ProductionRunnerMachineAuthority(
                    SchedulingControlPlane(workers["executor"]),
                    ExecutionControlPlane(workers["executor"]),
                    product_revision=case.product_revision,
                    image_digest=case.image_digest,
                ),
                _server_context(certificates["server"]),
                DurableRunnerControlCertificateAuthorizer(
                    RunnerCertificateAuthority(
                        workers["executor"], accepted_trust_bundle_versions=("test-v1",)
                    )
                ),
            )
            await server.start()
            client = MutualTlsRunnerControlClient(
                connect_host="localhost",
                port=server.port,
                server_name="localhost",
                tls_context=_client_context(certificates["runner"]),
                connection_generation=case.member.connection_generation,
                connection_token=case.connection_token,
            )
            try:
                assert await client.heartbeat_runner() == "online"
                try:
                    lease = await client.claim_run()
                except RunnerControlError as error:
                    pytest.fail(f"Control claim rejected: {error.code}")
                assert lease is not None and lease.run_id == UUID(admitted["run_id"])
                assert await client.claim_run() is None
                for status in ("starting", "running"):
                    await client.transition_run(lease, target_status=status)
                identity = SimpleNamespace(
                    runner_id=case.member.runner_id,
                    connection_generation=case.member.connection_generation,
                    product_revision=case.product_revision,
                    image_digest=case.image_digest,
                )
                authentication = sessionmaker(
                    applications["authenticator"], expire_on_commit=False
                )
                factory_runtime = ProductionInteractiveRuntimeFactory(
                    product_revision=case.product_revision,
                    image_digest=case.image_digest,
                    app_sessions=base.app_factory,
                    authenticator_sessions=authentication,
                    compatibility=load_runtime_compatibility_policy(
                        case.root / "saas/upstream-baseline.json"
                    ),
                    conversation_store=conversations,
                    permission_store=permissions,
                )
                kwargs = {
                    "identity": identity,
                    "control": client,
                    "runner_sessions": sessionmaker(case.runner_engine, expire_on_commit=False),
                    "fleet_source": case.source,
                }
                authorized, issued = await factory_runtime.authorize_model(lease=lease, **kwargs)
                assert (
                    authorized.run_id == lease.run_id
                    and authorized.runtime.actor_id == runtime.actor_id
                )
                assert authorized.event.data["content"][0]["text"] == "Build the requested page"
                assert issued.expires_at - datetime.now(timezone.utc) > timedelta(
                    hours=7, minutes=59
                )
                assert (await factory_runtime.authorize_model(lease=lease, **kwargs))[1] == issued
                credentials = ModelRunCredentialService(
                    app_sessions=base.app_factory,
                    authenticator_sessions=authentication,
                    compatibility=load_runtime_compatibility_policy(
                        case.root / "saas/upstream-baseline.json"
                    ),
                )
                claims = credentials.authenticate(issued.value)
                assert credentials.authorize(claims).claims.run_id == lease.run_id
                with pytest.raises(RunnerControlError):
                    await factory_runtime.authorize_model(
                        lease=replace(lease, capability_token="x" * 48), **kwargs
                    )
                if inference_probe is not None:

                    async def provision():
                        renewed_authority, credential = await factory_runtime.authorize_model(
                            lease=lease, **kwargs
                        )
                        assert renewed_authority == authorized
                        return credential

                    await asyncio.to_thread(
                        inference_probe,
                        SimpleNamespace(
                            fixture=fixture,
                            authorized=authorized,
                            lease=lease,
                            credentials=credentials,
                            provision=provision,
                            machine={
                                "runner_id": case.member.runner_id,
                                "connection_generation": case.member.connection_generation,
                            },
                        ),
                    )
                await client.transition_run(lease, target_status="succeeded")
                assert not await client.release_run(lease)
                assert await client.release_run(lease)
                with pytest.raises(PlatformModelGatewayTokenError):
                    credentials.authorize(claims)
                with factory() as database:
                    assert (
                        database.get(RunnerRegistrationRecord, case.member.runner_id).active_leases
                        == 0
                    )
                    assert database.get(RunRecord, lease.run_id).status == "succeeded"
                    assert database.get(RunDispatchRecord, lease.run_id).status == "released"
                    assert database.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
                    assert (
                        database.scalar(
                            sa.select(sa.func.count()).select_from(ModelRunTokenRecord)
                        )
                        == 1
                    )
            finally:
                await server.aclose()

        asyncio.run(run())


def test_signed_fleet_real_mtls_factory_issues_only_the_current_run_credential(
    isolated_postgres_url, tmp_path, db_uri, monkeypatch
):
    _signed_fleet(
        isolated_postgres_url,
        tmp_path,
        runtime_probe=lambda case: _factory_run(
            case, db_uri=db_uri, tmp_path=tmp_path, monkeypatch=monkeypatch
        ),
    )
