from __future__ import annotations

import copy
import ssl
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import RuntimePartitionRecord, RuntimePlacementRecord
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.runner_execution_spec import production_run_execution_spec
from saas.control_plane.scheduling import SchedulingError
from saas.control_plane.scheduling_models import CapabilityTokenRecord, RunDispatchRecord
from saas.production.runner_control import (
    MutualTlsRunnerControlClient,
    MutualTlsRunnerControlServer,
    ProductionRunnerMachineAuthority,
    RunnerControlError,
    _encoded,
    _lease_document,
)
from saas.production.runner_executor import ProductionHostIsolationExecutor
from tests.saas.test_interactive_execution_http import (
    _message,
    _post,
    _queued_worker,
    _scheduling,
)
from tests.saas.test_interactive_execution_http import (
    interactive_http as interactive_http,
)
from tests.saas.test_production_runner_control import (
    _CertificateAuthorizer,
    _certificates,
    _client_context,
    _server_context,
)


def _controller(f):
    scheduling, pool = _scheduling(f.factory, f.runtime, f.project_id)
    with f.factory() as db:
        placement = db.get(RuntimePlacementRecord, f.runtime.placement_id)
        domain, schema = placement.failure_domain, placement.official_schema_revision
    return scheduling, pool, domain, schema


def _register(f, scheduling, pool, domain, schema, *, key):
    with f.factory() as db:
        dispatch = db.scalars(sa.select(RunDispatchRecord)).first()
        required = dispatch.required_capabilities
        from saas.control_plane.scheduling_models import RunnerPoolRecord

        product_revision = db.get(RunnerPoolRecord, pool).source_revision
    return scheduling.register_runner(
        pool_id=pool,
        instance_key=key,
        failure_domain=domain,
        protocol_version=2,
        source_revision=product_revision,
        schema_revision=schema,
        adapter_contract_version=f.runtime.adapter_contract_version,
        capabilities=required,
        max_concurrency=2,
    )


def _admit(f, stable_id="a" * 32, *, text="Build the requested page"):
    admitted = _post(f, _message(stable_id=stable_id, text=text))
    assert admitted.status_code == 202, admitted.text
    assert _queued_worker(f.factory, f.factory).dispatch_once().published == 1
    return UUID(admitted.json()["run_id"])


def _claim(
    scheduling,
    connection,
    *,
    now=None,
    actions=("run.execute", "runtime.interactive.execute"),
    scope=None,
):
    return scheduling.claim_fair_run(
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        lease_duration=timedelta(seconds=5),
        capability_actions=["run.execute", "worktree.write"],
        capability_resource_scope=scope or {"control_plane": "runner_control"},
        interactive_capability_actions=actions,
        expected_product_revision="c" * 40,
        product_image_digest="sha256:" + "a" * 64,
        now=now,
    )


def test_exact_interactive_lease_binds_frozen_intent_and_only_runtime_actions(interactive_http):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    run_id = _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="interactive-controller")
    lease = _claim(scheduling, connection)
    assert lease is not None and lease.run_id == run_id
    envelope = lease.execution_envelope
    assert envelope is not None
    assert envelope.execution_kind == "omnigent.interactive.v1"
    assert envelope.change_set_id is None and envelope.launch_argv == ()
    with f.factory() as db:
        run = db.get(RunRecord, run_id)
        capability = db.get(CapabilityTokenRecord, lease.capability_id)
        assert run.status == "leased" and run.fence_token == 1
        assert envelope.execution_spec_hash == production_run_execution_spec(run.input).spec_hash
        assert set(capability.allowed_actions) == {"run.execute", "runtime.interactive.execute"}
        assert capability.resource_scope["session_id"] == str(run.session_id)
        assert capability.resource_scope["runtime_session_id"] == f.conversation.id
        assert capability.resource_scope["runtime_partition_generation"] == str(
            f.runtime.placement_generation
        )
    assert _claim(scheduling, connection) is None


def test_long_interactive_message_uses_a_bounded_content_free_control_reference(interactive_http):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    text = "long-private-interactive-input" * 4096
    admitted = _post(f, _message(text=text))
    assert admitted.status_code == 202, admitted.text
    assert _queued_worker(f.factory, f.factory).dispatch_once().published == 1
    connection = _register(f, scheduling, pool, domain, schema, key="bounded-controller")
    lease = _claim(scheduling, connection)
    assert lease is not None
    document = _lease_document(lease)
    encoded = _encoded(document)
    assert len(encoded) < 16_384
    assert text.encode() not in encoded
    assert "interactive_input" not in document["lease"]["execution_envelope"]
    with f.factory() as db:
        run = db.get(RunRecord, lease.run_id)
        assert run.input["execution"]["event"]["data"]["content"][0]["text"] == text
        assert (
            lease.execution_envelope.execution_spec_hash
            == production_run_execution_spec(run.input).spec_hash
        )


@pytest.mark.parametrize("generic_recovery", [False, True])
def test_expired_interactive_run_is_not_replayed_and_blocks_later_session_work(
    interactive_http, generic_recovery
):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    first, second = _admit(f), _admit(f, "b" * 32)
    connection = _register(f, scheduling, pool, domain, schema, key="interactive-controller")
    now = datetime.now(timezone.utc)
    lease = _claim(scheduling, connection, now=now)
    assert lease is not None and lease.run_id in {first, second}
    claimed, queued = lease.run_id, second if lease.run_id == first else first
    assert _claim(scheduling, connection, now=now) is None
    later = now + timedelta(seconds=6)
    if generic_recovery:
        recovered = ExecutionControlPlane(f.factory).recover_expired_runs(now=later)
        assert len(recovered) == 1 and recovered[0].status == "orphaned"
    scheduling.recover_expired_dispatches(now=later)
    with f.factory() as db:
        assert db.get(RunRecord, claimed).status == "orphaned"
        assert db.get(RunRecord, queued).status == "queued"
    assert _claim(scheduling, connection, now=later) is None


@pytest.mark.asyncio
async def test_real_message_outbox_and_mtls_control_lease_lifecycle(interactive_http, tmp_path):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    run_id = _admit(f, text="interactive input beyond the control frame limit" * 4096)
    connection = _register(f, scheduling, pool, domain, schema, key="tls-interactive-controller")
    certificates = _certificates(tmp_path, runner_id=connection.runner_id)
    authority = ProductionRunnerMachineAuthority(
        scheduling,
        ExecutionControlPlane(f.factory),
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
    )
    # Local CA/leaf transport is real; issuance authorization is a synthetic fixture.
    server = MutualTlsRunnerControlServer(
        authority, _server_context(certificates["server"]), _CertificateAuthorizer()
    )
    await server.start()
    client = MutualTlsRunnerControlClient(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        tls_context=_client_context(certificates["runner"]),
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
    )
    try:
        await client.heartbeat_runner()
        lease = await client.claim_run()
        assert lease is not None and lease.run_id == run_id
        with f.factory() as db:
            run = db.get(RunRecord, run_id)
            assert (
                lease.execution_envelope.execution_spec_hash
                == production_run_execution_spec(run.input).spec_hash
            )
        executor = object.__new__(ProductionHostIsolationExecutor)
        with pytest.raises(RunnerControlError) as rejected:
            executor._allocate_execution(lease)
        assert rejected.value.code == "runner_execution_kind_unsupported"
        await client.transition_run(lease, target_status="starting")
        await client.transition_run(lease, target_status="running")
        stopped = _post(f, {"type": "interrupt", "data": {}})
        assert stopped.status_code == 202, stopped.text
        assert (await client.heartbeat_run(lease))["status"] == "cancelling"
        await client.transition_run(lease, target_status="cancelled")
        await client.release_run(lease)
    finally:
        await server.aclose()
    with f.factory() as db:
        assert db.get(RunRecord, run_id).status == "cancelled"


def test_interactive_spec_binds_full_intent_without_exposing_it_as_a_shell_command(
    interactive_http,
):
    f = interactive_http
    _controller(f)
    run_id = _admit(f)
    with f.factory() as db:
        original = copy.deepcopy(db.get(RunRecord, run_id).input)
    spec = production_run_execution_spec(original)
    original["execution"]["event"]["data"]["content"][0]["text"] = "changed"
    assert spec.spec_hash != production_run_execution_spec(original).spec_hash
    assert spec.launch_argv == () and spec.change_set_id is None
    assert "Build the requested page" not in repr(spec)


def test_interactive_policy_and_scope_fail_before_issuing_a_capability(interactive_http):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    run_id = _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="strict-controller")
    for actions, scope, code in (
        (None, None, "interactive_executor_required"),
        (
            ("run.execute", "runtime.interactive.execute", "billing.record_usage"),
            None,
            "interactive_executor_policy_invalid",
        ),
        (
            ("run.execute", "runtime.interactive.execute"),
            {"runtime_session_id": "0" * 32},
            "capability_scope_conflict",
        ),
    ):
        with pytest.raises(SchedulingError) as rejected:
            _claim(scheduling, connection, actions=actions, scope=scope)
        assert rejected.value.code == code
        with f.factory() as db:
            assert db.get(RunRecord, run_id).status == "queued"
            assert db.scalar(sa.select(sa.func.count()).select_from(CapabilityTokenRecord)) == 0
    assert _claim(scheduling, connection) is not None


def test_runtime_route_is_rechecked_when_claimed_not_only_when_projected(interactive_http):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    run_id = _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="route-controller")
    with f.factory.begin() as db:
        db.execute(
            sa.update(RuntimePartitionRecord).values(
                placement_generation=f.runtime.placement_generation + 1
            )
        )
    with pytest.raises(SchedulingError) as rejected:
        _claim(scheduling, connection)
    assert rejected.value.code == "interactive_runtime_route_stale"
    with f.factory() as db:
        run = db.get(RunRecord, run_id)
        assert run.fence_token == 0 and run.lease_token is None
        assert db.scalar(sa.select(sa.func.count()).select_from(CapabilityTokenRecord)) == 0


def test_later_high_priority_message_cannot_overtake_the_session_predecessor(interactive_http):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    first, second = _admit(f), _admit(f, "b" * 32)
    now = datetime.now(timezone.utc)
    with f.factory.begin() as db:
        db.get(RunRecord, first).created_at = now - timedelta(seconds=2)
        later = db.get(RunRecord, second)
        later.created_at, later.priority = now - timedelta(seconds=1), 100
    connection = _register(f, scheduling, pool, domain, schema, key="ordered-controller")
    lease = _claim(scheduling, connection)
    assert lease is not None and lease.run_id == first


def test_session_predecessor_is_not_hidden_by_a_full_high_priority_claim_window(interactive_http):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    first = _admit(f)
    for index in range(65):
        response = _post(f, _message(stable_id=f"{index:032x}"))
        assert response.status_code == 202, response.text
    assert _queued_worker(f.factory, f.factory).dispatch_once().published == 65
    with f.factory.begin() as db:
        oldest = db.scalar(sa.select(sa.func.min(RunRecord.created_at)))
        db.get(RunRecord, first).created_at = oldest - timedelta(seconds=1)
        db.execute(sa.update(RunRecord).where(RunRecord.id != first).values(priority=100))
    connection = _register(f, scheduling, pool, domain, schema, key="window-controller")
    lease = _claim(scheduling, connection)
    assert lease is not None and lease.run_id == first


@pytest.mark.asyncio
async def test_interactive_control_client_rejects_misbound_or_command_envelopes(
    interactive_http, monkeypatch
):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="wire-controller")
    lease = _claim(scheduling, connection)
    assert lease is not None
    document = _lease_document(lease)
    context = ssl.create_default_context()
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    client = MutualTlsRunnerControlClient(
        connect_host="localhost",
        port=1,
        server_name="localhost",
        tls_context=context,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
    )
    for key, value in (
        ("launch_argv", ["not-an-interactive-command"]),
        ("change_set_id", str(lease.run_id)),
        ("execution_spec_hash", "invalid-hash"),
        ("interactive_input", {"execution": {"kind": "omnigent.agent.v1"}}),
        ("fence_token", lease.fence_token + 1),
    ):
        bad = copy.deepcopy(document)
        bad["lease"]["execution_envelope"][key] = value

        async def response(*_args, payload=bad, **_kwargs):
            return payload

        monkeypatch.setattr(client, "_request", response)
        with pytest.raises(RunnerControlError) as rejected:
            await client.claim_run()
        assert rejected.value.code == "runner_control_response_invalid"
