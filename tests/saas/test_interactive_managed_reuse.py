"""Warm-resource admission contracts; fake physical checks are not live provider proof."""

from __future__ import annotations

import asyncio
import json
from dataclasses import fields, replace
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from omnigent.host.frames import HostHelloFrame
from omnigent.server.host_registry import HostRegistry
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.production.interactive_driver import OfficialInteractiveDriver
from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    ManagedTerminationReceipt,
)
from saas.production.runner_control import (
    ProductionRunnerMachineAuthority,
    RunnerControlClientLease,
    RunnerControlError,
)
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_preparation import _reference
from tests.saas.test_interactive_managed_resources import _case, _resources
from tests.saas.test_interactive_managed_termination_records import _intent
from tests.saas.test_interactive_orphaned_retirement import _trusted_recovery
from tests.saas.test_interactive_runner_lease import _admit


async def _warm(c):
    authorize, prepare = c.executor._authorize, c.physical.prepare

    async def managed(lease):
        authorized, issued = await authorize(lease)
        return replace(
            authorized,
            launch={**authorized.launch, "host_type": "managed", "sandbox_provider": "kubernetes"},
        ), issued

    async def creating(actual, *, previous, on_launch, on_preparation, on_resources, on_creation):
        if previous is None:
            await on_preparation(_reference(host_id=actual.launch["host_id"]))
            for intent in (
                _intent(),
                _intent(secret_submitted=True),
                _intent(secret_submitted=True, secret_uid=_resources().token_secret_uid),
                _intent(
                    secret_submitted=True,
                    secret_uid=_resources().token_secret_uid,
                    workload_submitted=True,
                    input_template_sha256="a" * 64,
                ),
            ):
                await on_creation(intent)
            await on_resources(_resources())
        return await prepare(
            actual,
            previous=previous,
            on_launch=on_launch,
            on_preparation=on_preparation,
            on_resources=on_resources,
            on_creation=on_creation,
        )

    c.executor._authorize, c.physical.prepare = managed, creating
    control = ProductionRunnerMachineAuthority(
        SchedulingControlPlane(c.f.factory),
        ExecutionControlPlane(c.f.factory),
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
    )
    machine = {
        "runner_id": c.connection.runner_id,
        "connection_generation": c.connection.connection_generation,
        "connection_token": c.connection.connection_token,
    }

    async def finish(lease):
        assert await c.executor.prepare_finalization(lease, result="succeeded") == "succeeded"
        control.transition_run(
            **machine,
            run_id=lease.run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            capability_token=lease.capability_token,
            target_status="succeeded",
        )
        await c.executor.finalize(lease, result="succeeded")
        control.release_run(**machine, run_id=lease.run_id, fence_token=lease.fence_token)

    checks = []

    async def preflight(authorized, origins, *, previous=None):
        if not origins:
            return None
        (origin,) = origins
        (active,) = c.executor._active.values()
        assert not active.bound and active.preparation is None
        assert len(c.gateway_calls) == 1
        checks.append(origin.run_id)
        return origin

    c.physical.revalidate_managed = preflight
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    await finish(c.lease)
    root = c.journal.read(c.lease.run_id)
    _trusted_recovery(c)

    async def next_lease():
        run_id = _admit(c.f, "b" * 32, text="A distinct warm input")
        claimed = control.claim_run(**machine)
        assert claimed and claimed.run_id == run_id
        lease = RunnerControlClientLease(
            **{f.name: getattr(claimed, f.name) for f in fields(RunnerControlClientLease)}
        )
        for target in ("starting", "running"):
            control.transition_run(
                **machine,
                run_id=lease.run_id,
                lease_token=lease.lease_token,
                fence_token=lease.fence_token,
                capability_token=lease.capability_token,
                target_status=target,
            )
        return lease

    return SimpleNamespace(**locals())


@pytest.mark.asyncio
async def test_managed_warm_preflight_precedes_new_channel_and_persists_only_origin_reference(
    controller_case,
):
    c = controller_case
    w = await _warm(c)
    second = await w.next_lease()
    assert await c.executor.execute(second, cancellation=asyncio.Event()) == "succeeded"
    assert w.checks == [w.root.run_id]
    record = c.journal.read(second.run_id)
    assert record.managed_origin_run_id == w.root.run_id
    assert (
        record.managed_preparation is record.managed_creation is record.managed_resources is None
    )
    assert len(c.inputs) == len(c.gateway_calls) == 2
    path = c.journal.root / f"{second.run_id}.json"
    original = path.read_bytes()
    assert json.loads(original)["schema_version"] == 7
    for invalid in (None, uuid4()):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(record, managed_origin_run_id=invalid))
    try:
        for version in range(1, 7):
            value = json.loads(original)
            value["schema_version"] = version
            path.write_text(json.dumps(value))
            with pytest.raises(InteractiveRecoveryError):
                c.journal.read(second.run_id)
    finally:
        path.write_bytes(original)


@pytest.mark.asyncio
async def test_failed_managed_warm_preflight_cannot_bind_new_model_authority(controller_case):
    c = controller_case
    w = await _warm(c)
    second = await w.next_lease()

    async def rejected(*_args, **_kwargs):
        raise RunnerControlError("interactive_controller_unavailable", "Unavailable")

    c.physical.revalidate_managed = rejected
    with pytest.raises(RunnerControlError):
        await c.executor.execute(second, cancellation=asyncio.Event())
    active = c.executor._active[second.run_id]
    assert not active.bound and active.preparation is None
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("reject_after_cancel", [False, True])
async def test_cancellation_during_warm_preflight_is_not_a_failed_turn(
    controller_case, reject_after_cancel
):
    c = controller_case
    w = await _warm(c)
    second = await w.next_lease()
    entered, release, cancellation = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def pending(_authorized, origins, **_):
        entered.set()
        await release.wait()
        if reject_after_cancel:
            raise RunnerControlError("interactive_controller_unavailable", "Unavailable")
        return origins[0]

    c.physical.revalidate_managed = pending
    running = asyncio.create_task(c.executor.execute(second, cancellation=cancellation))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        cancellation.set()
        await c.executor.cancel(second)
        release.set()
        assert await asyncio.wait_for(running, 2) == "cancelled"
        active = c.executor._active[second.run_id]
        assert active.stopped and not active.bound and active.preparation is None
        assert active.record.managed_origin_run_id is None
        assert active.record.outcome != "failed"
        assert len(c.inputs) == len(c.gateway_calls) == 1
    finally:
        release.set()
        if not running.done():
            running.cancel()
        await asyncio.gather(running, return_exceptions=True)


@pytest.mark.asyncio
async def test_recorded_origin_retirement_blocks_warm_admission(controller_case):
    c = controller_case
    w = await _warm(c)
    c.journal.put(
        replace(
            w.root,
            managed_termination=ManagedTerminationReceipt(
                secret_uid=w.root.managed_creation.secret_uid
            ),
        )
    )
    second = await w.next_lease()
    with pytest.raises(RunnerControlError):
        await c.executor.execute(second, cancellation=asyncio.Event())
    assert not w.checks and len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
async def test_origin_changed_during_read_cannot_bind_model_authority(controller_case):
    c = controller_case
    w = await _warm(c)
    second = await w.next_lease()

    async def changed(_authorized, origins, **_):
        (origin,) = origins
        c.journal.put(
            replace(
                origin,
                managed_termination=ManagedTerminationReceipt(
                    secret_uid=origin.managed_creation.secret_uid
                ),
            )
        )
        return origin

    c.physical.revalidate_managed = changed
    with pytest.raises(RunnerControlError):
        await c.executor.execute(second, cancellation=asyncio.Event())
    assert not c.executor._active[second.run_id].bound
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
async def test_preparing_origin_reference_is_a_peer_before_host_launch(controller_case):
    c = controller_case
    w = await _warm(c)
    second = await w.next_lease()
    active, _ = await c.executor._prepare_active(second, cancellation=asyncio.Event())
    c.executor._put(
        active,
        host_id=None,
        official_runner_id=None,
        host_owner=None,
        host_account_generation=None,
        managed_origin_run_id=w.root.run_id,
    )
    assert c.executor._managed_peers(w.root) == [active.record]
    with pytest.raises(InteractiveRecoveryError):
        replace(active.record, managed_origin_run_id=active.record.run_id)
    with pytest.raises(InteractiveRecoveryError):
        replace(active.record, managed_preparation=_reference())


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
@pytest.mark.parametrize(
    "previous_runner,drift",
    [
        (previous, drift)
        for previous in (False, True)
        for drift in (None, "workload_uid", "secret_uid", "database_token", "owner", "detached")
    ]
    + [
        (True, drift) for drift in ("foreign_workspace", "peer_owner", "peer_generation", "runner")
    ],
)
async def test_reuse_reads_actual_resource_and_resolves_the_current_host_token(
    controller_case, tmp_path, monkeypatch, provider, previous_runner, drift
):
    c = controller_case
    k = _case(tmp_path, monkeypatch, provider)
    await asyncio.to_thread(k.wrap().start_host, "owned-job", host_id="c" * 32, token=k.token)
    origin = SimpleNamespace(
        runtime=c.context,
        managed_preparation=k.p.recorded[0],
        managed_creation=k.intents[-1],
        managed_resources=k.resources[0],
        managed_termination=None,
        host_owner=k.p.host.user_id,
        host_account_generation=None,
    )
    conversation = SimpleNamespace(host_id="c" * 32, runner_id="d" * 32)
    registry = HostRegistry()
    peer = registry.register(
        conversation.host_id,
        SimpleNamespace(),
        HostHelloFrame(version="0.1.0", frame_protocol_version=1, name="owned-host"),
        owner=origin.host_owner,
        workspace_id=c.context.physical_workspace_id,
    )
    assert registry.get(conversation.host_id) is None
    app = SimpleNamespace(
        state=SimpleNamespace(sandbox_config=k.p.deployment, host_registry=registry)
    )
    dependencies = SimpleNamespace(
        host_store=k.p.host_store,
        conversation_store=SimpleNamespace(get_conversation=lambda _: conversation),
    )
    driver = OfficialInteractiveDriver(
        app=app, dependencies=dependencies, contract_version="0.2.0"
    )
    authorized = replace(
        c.authorized,
        launch={**c.authorized.launch, "host_type": "managed", "sandbox_provider": provider},
    )
    if drift == "workload_uid":
        k.workload["metadata"]["uid"] = str(UUID(int=9))
    elif drift == "secret_uid":
        k.secret["metadata"]["uid"] = str(UUID(int=9))
    elif drift == "database_token":
        k.p.host_store.resolve_launch_token = lambda *_: None
    elif drift == "owner":
        k.p.host.user_id = "another-owner"
    elif drift == "detached":
        k.p.host.terminating_sandbox_id = k.p.host.sandbox_id
        k.p.host.sandbox_id = None
    before = k.p.trace.copy()
    previous = (
        SimpleNamespace(
            host_id=conversation.host_id,
            official_runner_id=conversation.runner_id,
            host_owner=origin.host_owner,
            host_account_generation=origin.host_account_generation,
        )
        if previous_runner
        else None
    )
    early_rejection = drift in {"foreign_workspace", "peer_owner", "peer_generation", "runner"}
    if drift == "foreign_workspace":
        registry.deregister(conversation.host_id, workspace_id=c.context.physical_workspace_id)
        registry.register(
            conversation.host_id,
            peer.ws,
            peer.hello,
            peer.owner,
            workspace_id=c.context.physical_workspace_id + 1,
        )
    elif drift == "peer_owner":
        peer.owner = "another-owner"
    elif drift == "peer_generation":
        peer.account_generation = 23
    elif drift == "runner":
        conversation.runner_id = "e" * 32
    if drift is None:
        assert await driver.revalidate_managed(authorized, (origin,), previous=previous) is origin
    else:
        with pytest.raises(RunnerControlError):
            await driver.revalidate_managed(authorized, (origin,), previous=previous)
    assert k.token not in str(k.p.trace)
    assert k.p.trace[len(before) :].count("close-client") == (0 if early_rejection else 1)
    assert not any(item.startswith("sdk-") for item in k.p.trace[len(before) :])
