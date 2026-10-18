from __future__ import annotations

from dataclasses import fields, replace
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from saas.compatibility import current_runtime_context
from saas.control_plane.db_models import (
    GlobalUser,
    ProjectMembershipRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.resolver import RuntimeCompatibilityPolicy
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.production.interactive_runtime import (
    InteractiveRuntimeAuthority,
    ProductionInteractiveRuntimeFactory,
)
from saas.production.runner_control import (
    MutualTlsRunnerControlClient,
    MutualTlsRunnerControlServer,
    ProductionRunnerMachineAuthority,
    RunnerControlClientLease,
    RunnerControlError,
)
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runner_lease import _admit, _controller, _register
from tests.saas.test_production_runner_control import (
    _CertificateAuthorizer,
    _certificates,
    _client_context,
    _server_context,
)


def _runtime_authority(f, connection, *, runner_sessions=None, app_sessions=None, control=None):
    class DomainControl:
        async def heartbeat_run(self, lease):
            authority = ProductionRunnerMachineAuthority(
                SchedulingControlPlane(f.factory), ExecutionControlPlane(f.factory)
            )
            result = authority.heartbeat_run(
                runner_id=connection.runner_id,
                connection_generation=connection.connection_generation,
                connection_token=connection.connection_token,
                run_id=lease.run_id,
                lease_token=lease.lease_token,
                fence_token=lease.fence_token,
                capability_token=lease.capability_token,
            )
            return {"status": result.status}

    with f.factory() as db:
        partition = db.get(RuntimePartitionRecord, f.runtime.runtime_partition_id)
        placement = db.get(RuntimePlacementRecord, f.runtime.placement_id)
        compatibility = RuntimeCompatibilityPolicy(
            runtime_type=partition.runtime_type,
            allowed_runtime_versions=frozenset({partition.runtime_version}),
            allowed_source_revisions=frozenset({partition.source_revision}),
            allowed_schema_revisions=frozenset({placement.official_schema_revision}),
            adapter_contract_version=partition.adapter_contract_version,
        )
    return InteractiveRuntimeAuthority(
        identity=SimpleNamespace(
            runner_id=connection.runner_id,
            connection_generation=connection.connection_generation,
            product_revision="c" * 40,
            image_digest="sha256:" + "a" * 64,
        ),
        control=control or DomainControl(),
        runner_sessions=runner_sessions or f.factory,
        app_sessions=app_sessions or f.factory,
        compatibility=compatibility,
        conversation_store=f.delegate,
        permission_store=f.permissions,
    )


def _running_lease(f):
    scheduling, pool, domain, schema = _controller(f)
    _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="runtime-controller")
    control = ProductionRunnerMachineAuthority(
        scheduling,
        ExecutionControlPlane(f.factory),
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
    )
    credentials = {
        "runner_id": connection.runner_id,
        "connection_generation": connection.connection_generation,
        "connection_token": connection.connection_token,
    }
    claimed = control.claim_run(**credentials)
    assert claimed is not None
    for target in ("starting", "running"):
        control.transition_run(
            **credentials,
            run_id=claimed.run_id,
            lease_token=claimed.lease_token,
            fence_token=claimed.fence_token,
            capability_token=claimed.capability_token,
            target_status=target,
        )
    lease = RunnerControlClientLease(
        **{field.name: getattr(claimed, field.name) for field in fields(RunnerControlClientLease)}
    )
    return lease, connection


@pytest.mark.asyncio
async def test_runtime_reauthorization_binds_official_transaction_initializer(
    interactive_http, monkeypatch
):
    from omnigent.db.utils import _managed_session_initializer
    from saas.production import interactive_runtime as module

    fixture = interactive_http
    lease, connection = _running_lease(fixture)
    original = module.require_access_and_level
    checked = []

    async def require_initialized_transaction(*args, **kwargs):
        assert _managed_session_initializer.get() is not None
        checked.append(current_runtime_context().physical_workspace_id)
        return await original(*args, **kwargs)

    monkeypatch.setattr(module, "require_access_and_level", require_initialized_transaction)
    authorized = await _runtime_authority(fixture, connection).authorize(lease)
    assert checked == [fixture.runtime.physical_workspace_id]
    assert authorized.session_id == fixture.conversation.id
    assert _managed_session_initializer.get() is None


@pytest.mark.asyncio
async def test_real_claim_reads_original_input_and_reauthorizes_its_real_user(interactive_http):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    verified = []
    authority._verify_machine_database = lambda: verified.append("verified")
    authorized = await authority.authorize(lease)
    assert verified == ["verified"]
    assert authorized.run_id == lease.run_id
    assert authorized.runtime.actor_id == f.runtime.actor_id
    assert authorized.runtime.project_id == f.project_id
    assert authorized.runtime.runtime_user_key == f.runtime.runtime_user_key
    assert authorized.runtime.physical_workspace_id == 41
    assert authorized.session_id == f.conversation.id
    assert authorized.launch["host_id"] == f.conversation.host_id
    assert authorized.publication == f.marker
    assert authorized.event.data["content"][0]["text"] == "Build the requested page"
    assert "Build the requested page" not in repr(authorized)
    with pytest.raises(RuntimeError):
        current_runtime_context()

    def drifted():
        raise RunnerControlError("interactive_runtime_database_unavailable", "fleet changed")

    authority._verify_machine_database = drifted
    with pytest.raises(RunnerControlError, match="fleet changed"):
        await authority.authorize(lease)


@pytest.mark.asyncio
async def test_runtime_read_uses_the_actual_mtls_capability_authority(interactive_http, tmp_path):
    f = interactive_http
    lease, connection = _running_lease(f)
    certificates = _certificates(tmp_path, runner_id=connection.runner_id)
    machine = ProductionRunnerMachineAuthority(
        SchedulingControlPlane(f.factory), ExecutionControlPlane(f.factory)
    )
    server = MutualTlsRunnerControlServer(
        machine, _server_context(certificates["server"]), _CertificateAuthorizer()
    )
    await server.start()
    control = MutualTlsRunnerControlClient(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        tls_context=_client_context(certificates["runner"]),
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
    )
    try:
        authority = _runtime_authority(f, connection, control=control)
        authorized = await authority.authorize(lease)
        assert authorized.run_id == lease.run_id
        assert authorized.runtime.actor_id == f.runtime.actor_id
        with pytest.raises(RunnerControlError, match="Runtime authority changed"):
            await authority.authorize(replace(lease, capability_token="x" * 48))
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_runtime_does_not_treat_a_missing_permission_store_as_single_user(interactive_http):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    authority._permissions = None
    with pytest.raises(RunnerControlError, match="Runtime authority changed"):
        await authority.authorize(lease)


@pytest.mark.parametrize("tamper", ["capability", "fence", "digest", "run_id"])
@pytest.mark.asyncio
async def test_runtime_read_rejects_a_forged_claim_before_user_projection(
    interactive_http, tamper
):
    f = interactive_http
    lease, connection = _running_lease(f)
    if tamper == "capability":
        lease = replace(lease, capability_token="not-the-claimed-capability-token")
    elif tamper == "fence":
        lease = replace(lease, fence_token=lease.fence_token + 1)
    else:
        envelope = lease.execution_envelope
        assert envelope is not None
        values = (
            {"execution_spec_hash": "0" * 64}
            if tamper == "digest"
            else {"run_id": connection.runner_id}
        )
        lease = replace(lease, execution_envelope=replace(envelope, **values))
    with pytest.raises(RunnerControlError, match="Runtime authority changed"):
        await _runtime_authority(f, connection).authorize(lease)


@pytest.mark.parametrize("drift", ["user", "project", "generation", "runtime_project"])
@pytest.mark.asyncio
async def test_runtime_execution_rechecks_live_delegation_after_claim(interactive_http, drift):
    f = interactive_http
    lease, connection = _running_lease(f)
    with f.factory.begin() as db:
        if drift == "user":
            db.get(GlobalUser, f.runtime.actor_id).status = "suspended"
        elif drift == "project":
            db.execute(sa.update(ProjectMembershipRecord).values(status="revoked"))
        elif drift == "generation":
            db.get(
                RuntimePartitionRecord, f.runtime.runtime_partition_id
            ).placement_generation += 1
        else:
            db.execute(
                sa.update(RuntimeResourceBindingRecord)
                .where(RuntimeResourceBindingRecord.resource_type == "project")
                .values(runtime_resource_id="d" * 32)
            )
    with pytest.raises((PermissionError, RunnerControlError)):
        await _runtime_authority(f, connection).authorize(lease)


def test_production_server_binds_the_runtime_to_the_existing_adapter(tmp_path, monkeypatch):
    from saas.production import server as server_module
    from saas.production.server import ProductionExternalAdapters, build_production_server
    from tests.saas.test_production_server import _config, _fake_official_app, _official, _sessions

    class RuntimeAdapter:
        def __init__(self):
            self.binding = None

        def assert_production_ready(self):
            pass

        def bind_runtime(self, **binding):
            self.binding = binding

    sessions, official, adapter = _sessions(), _official(), RuntimeAdapter()
    monkeypatch.setattr(server_module, "create_omnigent_saas_app", _fake_official_app)
    built = None
    try:
        built = build_production_server(
            _config(tmp_path, capabilities=frozenset({"tenant", "run", "runner"})),
            sessions,
            official=official,
            external=ProductionExternalAdapters(runner=adapter),
        )
        assert adapter.binding["app"] is built.app
        assert adapter.binding["official"] is official
        assert adapter.binding["auth_provider"] is built.services.integration.auth_provider
        factory = adapter.binding["runtime"]
        assert isinstance(factory, ProductionInteractiveRuntimeFactory)
        assert built.app.state.production_interactive_runtime is factory
        wrong_release = SimpleNamespace(
            product_revision="0" * 40, image_digest="sha256:" + "3" * 64
        )
        with pytest.raises(RunnerControlError, match="Runtime authority changed"):
            factory.create_authority(
                identity=wrong_release, control=None, runner_sessions=sessions.app, fleet_source={}
            )
    finally:
        if built is not None:
            built.close()
        else:
            sessions.close()


def test_runtime_binding_failure_redacts_diagnostics_and_closes_composition(tmp_path, monkeypatch):
    from saas.production import server as server_module
    from saas.production.server import (
        ProductionExternalAdapters,
        ProductionServerCompositionError,
        build_production_server,
    )
    from tests.saas.test_production_server import _config, _fake_official_app, _official, _sessions

    class BrokenRuntimeAdapter:
        def __init__(self):
            self.app = None

        def assert_production_ready(self):
            pass

        def bind_runtime(self, **binding):
            self.app = binding["app"]
            raise RuntimeError("synthetic-private-database-diagnostic")

    sessions, adapter = _sessions(), BrokenRuntimeAdapter()
    monkeypatch.setattr(server_module, "create_omnigent_saas_app", _fake_official_app)
    try:
        with pytest.raises(ProductionServerCompositionError) as rejected:
            build_production_server(
                _config(tmp_path, capabilities=frozenset({"tenant", "run", "runner"})),
                sessions,
                official=_official(),
                external=ProductionExternalAdapters(runner=adapter),
            )
        assert str(rejected.value) == "production interactive Runtime binding failed"
        assert rejected.value.__cause__ is None
        assert adapter.app.state.production_saas_services._closed
    finally:
        sessions.close()
