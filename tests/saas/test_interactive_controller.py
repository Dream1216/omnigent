"""Controller/domain contracts; scripted physical driver is not production Agent or PKI proof."""

from __future__ import annotations

import asyncio
import copy
import json
import threading
from dataclasses import fields, replace
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
import sqlalchemy as sa
from fastapi import FastAPI

from omnigent.host.frames import HostLaunchRunnerFrame
from omnigent.runner.identity import token_bound_runner_id
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunEventRecord, RunRecord
from saas.control_plane.interactive_run_route import interactive_session_identity
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.production.interactive_controller import ProductionInteractiveExecutor
from saas.production.interactive_driver import InteractiveTurnObservation
from saas.production.interactive_model_channel import (
    SessionModelChannelMiddleware,
    SessionModelChannels,
    consume_host_model_channel,
    model_channel_configuration,
)
from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    InteractiveRecoveryJournal,
    physical_recovery_proof_sha256,
)
from saas.production.runner_control import (
    ProductionRunnerMachineAuthority,
    RunnerControlClientLease,
    RunnerControlError,
)
from saas.runner_adapter.metering import ManagedMeteringGrant, ProviderUsageMeter
from tests.saas.test_gateway_usage_delivery import ReferenceClient
from tests.saas.test_interactive_execution_http import _managed_create, _post
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_model_channel import ORIGIN
from tests.saas.test_interactive_runner_lease import _admit
from tests.saas.test_interactive_runtime import _running_lease, _runtime_authority
from tests.saas.test_model_run_credentials import _service
from tests.saas.test_production_runner_control import _certificates


@pytest.fixture
async def controller_case(interactive_http, tmp_path):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    service = _service(f, authority)
    authorized = await authority.authorize(lease)
    context = authorized.runtime
    scope_id = interactive_session_identity(
        context.tenant_id, context.space_id, context.runtime_partition_id, authorized.session_id
    )
    certificates = _certificates(tmp_path, runner_id=connection.runner_id)
    certificate = certificates["runner"]
    journal = InteractiveRecoveryJournal(tmp_path / "controller-private")
    channels = SessionModelChannels(public_origin=ORIGIN)
    references = ReferenceClient()
    gateway_calls, inputs, stops = [], [], []
    done, prepared = asyncio.Event(), asyncio.Event()
    gateway_started, gateway_release = asyncio.Event(), asyncio.Event()
    controls = SimpleNamespace(
        stop_ack=True, auto_complete=True, unknown_fee=False, pause_gateway=False
    )

    async def authorize(current):
        actual = await authority.authorize(current)
        return actual, service.issue(actual, current)

    def grant(actual, current):
        return ManagedMeteringGrant(
            scope_id,
            current.run_id,
            connection.runner_id,
            current.capability_token,
            current.expires_at,
            "https://billing.internal",
            "billing.internal",
            certificate.ca,
            certificate.certificate,
            certificate.private_key,
            journal.root / "usage" / str(current.run_id),
        )

    async def supplier(request):
        gateway_calls.append(request)
        assert request.headers["Authorization"].startswith("Bearer mrt_")
        assert lease.capability_token not in str(request.headers)
        if controls.pause_gateway:
            gateway_started.set()
            await gateway_release.wait()
        references.available = not controls.unknown_fee
        return httpx.Response(200, stream=httpx.ByteStream(b'data: {"done":true}\n\n'))

    class Physical:
        channel = None

        def assert_production_ready(self):
            pass

        async def prepare(self, actual, *, previous, on_launch):
            if previous is not None:
                assert previous.channel_value == self.channel.secret_value
                prepared.set()
                return object()
            publication = authority._catalog.require_version(actual.runtime, actual.publication)
            harness = "codex" if publication["wire_api"] == "openai_responses" else "openai-agents"
            config = model_channel_configuration(
                public_origin=ORIGIN, session_id=scope_id, harness=harness, publication=publication
            )
            frame = HostLaunchRunnerFrame(
                "request", "x" * 43, "/workspace", actual.session_id, harness, config
            )
            peer = SimpleNamespace(
                host_id=actual.launch["host_id"],
                owner=actual.runtime.runtime_user_key,
                account_generation=None,
            )
            frame = await on_launch(frame, peer)
            clean, self.channel = consume_host_model_channel(frame, server_url=ORIGIN)
            assert "capability_token" not in json.dumps(clean.inference_config)
            app = SessionModelChannelMiddleware(FastAPI(), channels=channels)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
                result = await client.post(
                    self.channel.base_url + "/responses",
                    headers={"Authorization": "Bearer " + self.channel.secret_value},
                    json={},
                )
                assert (
                    result.status_code == 503
                )  # Initialization cannot infer before input admission.
            prepared.set()
            return object()

        async def dispatch(self, actual, _handle):
            inputs.append(copy.deepcopy(actual.event.model_dump()))
            app = SessionModelChannelMiddleware(FastAPI(), channels=channels)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
                result = await client.post(
                    self.channel.base_url + "/responses",
                    headers={"Authorization": "Bearer " + self.channel.secret_value},
                    json={},
                )
                assert result.status_code == 200
            if controls.auto_complete:
                done.set()

        async def outcome(self, _actual, _handle):
            await done.wait()
            return "succeeded"

        async def quiesce_preparation(self, _authorized):
            pass

        async def stop(self, record):
            stops.append(record.official_runner_id)
            return controls.stop_ack and record.official_runner_id is not None

        async def release(self, _handle):
            pass

    physical = Physical()
    recovered, confirmed = [], []

    async def verify(record):
        authority.verify_recovery(record)
        recovered.append(record.run_id)

    async def confirm(record):
        assert record.process_stopped
        confirmed.append(record.run_id)

    executor = ProductionInteractiveExecutor(
        authorize_model=authorize,
        grant_for_run=grant,
        driver=physical,
        journal=journal,
        recovery_certificate_path=certificate.certificate,
        channels=channels,
        connection_generation=connection.connection_generation,
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
        assert_authority=lambda: None,
        verify_recovery=verify,
        confirm_recovery=confirm,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(supplier)),
        meter_factory=lambda value: ProviderUsageMeter(
            grant=value, client=references, gateway_managed=True, retry_interval_seconds=0.05
        ),
    )
    case = SimpleNamespace(**locals())
    yield case
    for active in tuple(executor._active.values()):
        await executor._seal(active)
        active.meter.close(timeout_seconds=0)
    journal.close()


def _release_never_started(c, terminal):
    control = ExecutionControlPlane(c.f.factory)
    at = c.lease.expires_at - timedelta(seconds=1)
    for status in (*(("cancelling",) if terminal == "cancelled" else ()), terminal):
        control.transition_run(
            run_id=c.lease.run_id,
            lease_token=c.lease.lease_token,
            fence_token=c.lease.fence_token,
            target_status=status,
            trace_id="isolated-never-started",
            now=at,
        )
    SchedulingControlPlane(c.f.factory).release_dispatch(
        run_id=c.lease.run_id,
        runner_id=c.connection.runner_id,
        connection_generation=c.connection.connection_generation,
        connection_token=c.connection.connection_token,
        fence_token=c.lease.fence_token,
        requeue=False,
        now=at,
    )


def _confirm_never_started(c, *, lost_ack=False):
    proofs = []

    async def verify(record):
        assert record.run_id == c.lease.run_id and record.process_stopped
        assert getattr(record, "official_runner_id", None) is None

    async def confirm(record):
        proof = physical_recovery_proof_sha256(record)
        proofs.append(proof)
        SchedulingControlPlane(c.f.factory).confirm_interactive_recovery(
            runner_id=c.connection.runner_id,
            connection_generation=c.connection.connection_generation,
            connection_token=c.connection.connection_token,
            run_id=c.lease.run_id,
            fence_token=c.lease.fence_token,
            capability_token=c.lease.capability_token,
            proof_sha256=proof,
            certificate_fingerprint_sha256="a" * 64,
            expected_product_revision="c" * 40,
            product_image_digest="sha256:" + "a" * 64,
            cleanup_kind="never_started",
        )
        if lost_ack and len(proofs) == 1:
            raise RunnerControlError("isolated_receipt_ack_lost", "Unavailable")

    c.executor._verify_recovery, c.executor._confirm_recovery = verify, confirm
    return proofs


@pytest.mark.asyncio
@pytest.mark.parametrize("lost_ack", [False, True])
async def test_initial_model_auth_failure_retains_never_started_proof_without_replay(
    controller_case, lost_ack
):
    c = controller_case

    async def rejected(_lease):
        raise RunnerControlError("isolated_model_auth_unavailable", "Unavailable")

    c.executor._authorize = rejected
    proofs = _confirm_never_started(c, lost_ack=lost_ack)
    with pytest.raises(RunnerControlError):
        await c.executor.execute(c.lease, cancellation=asyncio.Event())
    assert not c.prepared.is_set() and not c.inputs and not c.gateway_calls and not c.stops
    assert await c.executor.prepare_finalization(c.lease, result="failed") == "failed"
    await c.executor.finalize(c.lease, result="failed")
    _release_never_started(c, "failed")
    if lost_ack:
        with pytest.raises(RunnerControlError, match="Unavailable"):
            await c.executor.reconcile_physical_gc(limit=32)
    restored_journal = None
    executor = c.executor
    if lost_ack:
        c.journal.close()
        restored_journal = InteractiveRecoveryJournal(c.journal.root)
        executor = ProductionInteractiveExecutor(
            authorize_model=c.executor._authorize,
            grant_for_run=c.executor._grant,
            driver=c.physical,
            journal=restored_journal,
            recovery_certificate_path=c.certificate.certificate,
            channels=SessionModelChannels(public_origin=ORIGIN),
            connection_generation=c.connection.connection_generation,
            product_revision="c" * 40,
            image_digest="sha256:" + "a" * 64,
            assert_authority=lambda: None,
            verify_recovery=c.executor._verify_recovery,
            confirm_recovery=c.executor._confirm_recovery,
            meter_factory=c.executor._meter_factory,
        )
    try:
        assert await executor.reconcile_physical_gc(limit=32) == 1
        assert len(proofs) == (2 if lost_ack else 1) and len(set(proofs)) == 1
        assert await executor.reconcile_physical_gc(limit=32) == 0
    finally:
        if restored_journal is not None:
            restored_journal.close()
    assert not c.prepared.is_set() and not c.inputs and not c.gateway_calls and not c.stops
    with c.f.factory() as db:
        assert db.get(RunRecord, c.lease.run_id).status == "failed"
        events = db.scalars(
            sa.select(RunEventRecord).where(
                RunEventRecord.run_id == c.lease.run_id,
                RunEventRecord.event_type == "run.interactive_physical_recovered",
            )
        ).all()
        assert len(events) == 1 and events[0].payload["proof_sha256"] == proofs[0]
        assert events[0].payload["cleanup_kind"] == "never_started"


@pytest.mark.asyncio
async def test_cancellation_before_any_preparation_retains_never_started_terminal_receipt(
    controller_case,
):
    c = controller_case
    proofs = _confirm_never_started(c)
    cancellation = asyncio.Event()
    cancellation.set()
    assert await c.executor.execute(c.lease, cancellation=cancellation) == "cancelled"
    assert await c.executor.prepare_finalization(c.lease, result="cancelled") == "cancelled"
    await c.executor.finalize(c.lease, result="cancelled")
    _release_never_started(c, "cancelled")
    assert await c.executor.reconcile_physical_gc(limit=32) == 1
    assert len(proofs) == 1 and not c.prepared.is_set()
    assert not c.inputs and not c.gateway_calls and not c.stops
    assert await c.executor.reconcile_physical_gc(limit=32) == 0


@pytest.mark.asyncio
async def test_pending_usage_flush_does_not_hold_the_public_stop_lifecycle(controller_case):
    c = controller_case
    c.controls.unknown_fee = True
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    assert await c.executor.prepare_finalization(c.lease, result="succeeded") == "succeeded"
    await c.executor.finalize(c.lease, result="succeeded")
    entered, resume = threading.Event(), threading.Event()

    class PausedMeter:
        def flush(self, _timeout):
            entered.set()
            assert resume.wait(5)

        def close(self, _timeout):
            pass

    c.executor._meter_factory = lambda _grant: PausedMeter()
    collecting = asyncio.create_task(c.executor.reconcile_physical_gc(limit=32))

    async def cancel_inputs():
        return {"queued": False, "physical_run_id": str(c.lease.run_id)}

    try:
        assert await asyncio.to_thread(entered.wait, 2)
        await asyncio.wait_for(
            c.executor.stop_session(
                c.context,
                c.authorized.session_id,
                c.journal.read(c.lease.run_id).official_runner_id,
                cancel_inputs,
            ),
            1,
        )
        record = c.journal.read(c.lease.run_id)
        assert record.process_stopped and record.outcome == "succeeded"
        assert list(record.grant.spool_directory.glob("*.pending.json"))
    finally:
        resume.set()
        await asyncio.wait_for(collecting, 2)
    assert len(c.stops) == 1 and len(c.inputs) == 1


@pytest.mark.asyncio
async def test_gc_rechecks_a_later_candidate_after_an_earlier_pending_record_waits(
    controller_case, monkeypatch
):
    c = controller_case
    c.controls.unknown_fee = True
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

    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    await finish(c.lease)
    first = c.journal.read(c.lease.run_id)
    assert list(first.grant.spool_directory.glob("*.pending.json"))
    second_id = _admit(c.f, "b" * 32, text="Continue without replay")
    claimed = control.claim_run(**machine)
    assert claimed is not None and claimed.run_id == second_id
    second = RunnerControlClientLease(
        **{field.name: getattr(claimed, field.name) for field in fields(RunnerControlClientLease)}
    )
    for target in ("starting", "running"):
        control.transition_run(
            **machine,
            run_id=second.run_id,
            lease_token=second.lease_token,
            fence_token=second.fence_token,
            capability_token=second.capability_token,
            target_status=target,
        )
    assert await c.executor.execute(second, cancellation=asyncio.Event()) == "succeeded"
    records = c.journal.records
    monkeypatch.setattr(
        c.journal, "records", lambda: sorted(records(), key=lambda row: row.run_id != first.run_id)
    )
    entered, resume = asyncio.Event(), asyncio.Event()
    verify = c.executor._verify_recovery

    async def pause_first(record):
        await verify(record)
        if record.run_id == first.run_id:
            entered.set()
            await resume.wait()

    monkeypatch.setattr(c.executor, "_verify_recovery", pause_first)
    collecting = asyncio.create_task(c.executor.reconcile_physical_gc(limit=32))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        await finish(second)
    finally:
        resume.set()
    assert await asyncio.wait_for(collecting, 2) == 2
    assert c.journal.read(second.run_id).outcome == "succeeded"
    assert not c.stops and not c.confirmed
    assert len(c.inputs) == len(c.gateway_calls) == 2


@pytest.mark.asyncio
async def test_real_admitted_run_dispatches_one_original_input_and_closes_model_admission(
    controller_case,
):
    c = controller_case
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    assert c.inputs == [c.authorized.event.model_dump()]
    assert len(c.gateway_calls) == 1
    assert await c.executor.prepare_finalization(c.lease, result="succeeded") == "succeeded"
    await c.executor.prepare_terminal_transition(c.lease)
    await c.executor.finalize(c.lease, result="succeeded")
    record = c.journal.read(c.lease.run_id)
    assert record.phase == "terminal" and record.outcome == "succeeded"
    assert not record.process_stopped and not c.stops
    assert c.lease.capability_token not in repr(record)
    assert c.physical.channel.secret_value not in repr(record)
    assert record.grant.capability_token == c.lease.capability_token
    assert not list(record.grant.spool_directory.glob("*.pending.json"))
    c.executor.assert_claimable()


@pytest.mark.asyncio
async def test_two_real_runs_keep_one_host_channel_but_never_reuse_model_or_metering_authority(
    controller_case,
):
    c = controller_case
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
        assert await c.executor.execute(lease, cancellation=asyncio.Event()) == "succeeded"
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
        control.release_run(
            **machine,
            run_id=lease.run_id,
            fence_token=lease.fence_token,
        )

    await finish(c.lease)
    first = c.journal.read(c.lease.run_id)
    second_id = _admit(c.f, "b" * 32, text="Continue this same session")
    claimed = control.claim_run(**machine)
    assert claimed is not None and claimed.run_id == second_id
    second = RunnerControlClientLease(
        **{field.name: getattr(claimed, field.name) for field in fields(RunnerControlClientLease)}
    )
    for target in ("starting", "running"):
        control.transition_run(
            **machine,
            run_id=second.run_id,
            lease_token=second.lease_token,
            fence_token=second.fence_token,
            capability_token=second.capability_token,
            target_status=target,
        )
    await finish(second)
    latest = c.journal.read(second.run_id)
    assert latest.channel_value == first.channel_value
    assert latest.official_runner_id == first.official_runner_id
    assert latest.grant.capability_token != first.grant.capability_token
    assert len(c.inputs) == len(c.gateway_calls) == 2 and not c.stops
    assert (
        c.gateway_calls[0].headers["authorization"] != c.gateway_calls[1].headers["authorization"]
    )
    assert {call["run_id"] for call in c.references.calls} == {c.lease.run_id, second.run_id}


@pytest.mark.asyncio
async def test_cancelling_unknown_preparation_cannot_invent_a_stop_ack(controller_case):
    c = controller_case

    async def preparing(*args, **kwargs):
        c.prepared.set()
        await asyncio.Event().wait()

    c.physical.prepare = preparing
    cancellation = asyncio.Event()
    execution = asyncio.create_task(c.executor.execute(c.lease, cancellation=cancellation))
    await asyncio.wait_for(c.prepared.wait(), 2)
    cancellation.set()
    await c.executor.cancel(c.lease)
    assert await execution == "orphaned"
    assert await c.executor.prepare_finalization(c.lease, result="cancelled") == "orphaned"
    with pytest.raises(RunnerControlError):
        await c.executor.finalize(c.lease, result="orphaned")
    assert not c.inputs and not c.journal.read(c.lease.run_id).process_stopped


@pytest.mark.asyncio
async def test_cancellation_cannot_forget_an_existing_idle_runner(controller_case):
    c = controller_case
    await c.executor.execute(c.lease, cancellation=asyncio.Event())
    active = c.executor._active[c.lease.run_id]
    c.executor._put(active, phase="prepared")
    active.preparation = None
    c.controls.stop_ack = False
    await c.executor.cancel(c.lease)
    assert not active.stopped and not active.record.process_stopped
    assert c.stops == [active.record.official_runner_id]


@pytest.mark.asyncio
@pytest.mark.parametrize("ack", [False, True])
async def test_public_idle_stop_updates_recovery_only_after_exact_ack(controller_case, ack):
    c = controller_case
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    assert await c.executor.prepare_finalization(c.lease, result="succeeded") == "succeeded"
    await c.executor.finalize(c.lease, result="succeeded")
    c.controls.stop_ack = ack
    cancellations = []

    async def cancel_inputs():
        cancellations.append(True)
        return {"queued": False, "physical_run_id": str(c.lease.run_id)}

    stop = c.executor.stop_session(
        c.context,
        c.authorized.session_id,
        c.journal.read(c.lease.run_id).official_runner_id,
        cancel_inputs,
    )
    if ack:
        await stop
    else:
        with pytest.raises(RunnerControlError):
            await stop
    record = c.journal.read(c.lease.run_id)
    assert record.phase == "terminal" and record.outcome == "succeeded"
    assert record.process_stopped is ack
    assert len(cancellations) == len(c.stops) == 1
    assert await c.executor.reconcile_physical_gc(limit=32) == int(ack)
    assert c.confirmed == ([c.lease.run_id] if ack else [])
    assert c.journal.read(c.lease.run_id).outcome == "succeeded"


@pytest.mark.asyncio
async def test_public_active_stop_wakes_execution_without_task_replay(controller_case):
    c = controller_case
    c.controls.auto_complete = False
    execution = asyncio.create_task(c.executor.execute(c.lease, cancellation=asyncio.Event()))
    await asyncio.wait_for(c.prepared.wait(), 2)
    while not c.inputs:
        await asyncio.sleep(0)

    async def cancel_inputs():
        return {"queued": False, "physical_run_id": str(c.lease.run_id)}

    await c.executor.stop_session(
        c.context,
        c.authorized.session_id,
        c.journal.read(c.lease.run_id).official_runner_id,
        cancel_inputs,
    )
    assert await asyncio.wait_for(execution, 2) == "cancelled"
    assert await c.executor.prepare_finalization(c.lease, result="cancelled") == "cancelled"
    await c.executor.finalize(c.lease, result="cancelled")
    assert len(c.inputs) == len(c.stops) == 1


@pytest.mark.asyncio
async def test_public_stop_waits_for_completed_run_then_stops_idle_runner(controller_case):
    c = controller_case
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"

    async def cancel_inputs():
        return {"queued": False, "physical_run_id": str(c.lease.run_id)}

    stopping = asyncio.create_task(
        c.executor.stop_session(
            c.context,
            c.authorized.session_id,
            c.journal.read(c.lease.run_id).official_runner_id,
            cancel_inputs,
        )
    )
    await asyncio.sleep(0)
    assert not stopping.done() and not c.stops
    assert await c.executor.prepare_finalization(c.lease, result="succeeded") == "succeeded"
    await c.executor.prepare_terminal_transition(c.lease)
    await c.executor.finalize(c.lease, result="succeeded")
    await asyncio.wait_for(stopping, 2)
    record = c.journal.read(c.lease.run_id)
    assert record.process_stopped and record.outcome == "succeeded"


@pytest.mark.asyncio
async def test_public_stop_does_not_wait_for_a_wedged_dispatch(controller_case):
    c = controller_case
    c.controls.pause_gateway = True
    execution = asyncio.create_task(c.executor.execute(c.lease, cancellation=asyncio.Event()))
    await asyncio.wait_for(c.gateway_started.wait(), 2)

    async def cancel_inputs():
        return {"queued": False, "physical_run_id": str(c.lease.run_id)}

    await asyncio.wait_for(
        c.executor.stop_session(
            c.context,
            c.authorized.session_id,
            c.journal.read(c.lease.run_id).official_runner_id,
            cancel_inputs,
        ),
        1,
    )
    assert await asyncio.wait_for(execution, 2) == "cancelled"
    assert c.journal.read(c.lease.run_id).process_stopped
    assert len(c.inputs) == len(c.stops) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("runner_id,required", [(None, True), ("foreign-runner", False)])
async def test_public_stop_cannot_confirm_an_unowned_physical_process(
    controller_case, runner_id, required
):
    c = controller_case

    async def cancel_inputs():
        return {"queued": False, **({"physical_run_id": str(c.lease.run_id)} if required else {})}

    with pytest.raises(RunnerControlError):
        await c.executor.stop_session(c.context, c.authorized.session_id, runner_id, cancel_inputs)
    assert not c.stops


@pytest.mark.asyncio
async def test_exact_runner_cancellation_ack_is_idempotent_after_public_cancel(controller_case):
    from saas.control_plane.execution import ExecutionControlPlaneError

    c = controller_case
    assert _post(c.f, {"type": "interrupt", "data": {}}).status_code == 202
    authority = ProductionRunnerMachineAuthority(
        SchedulingControlPlane(c.f.factory), ExecutionControlPlane(c.f.factory)
    )
    command = {
        "runner_id": c.connection.runner_id,
        "connection_generation": c.connection.connection_generation,
        "connection_token": c.connection.connection_token,
        "run_id": c.lease.run_id,
        "lease_token": c.lease.lease_token,
        "fence_token": c.lease.fence_token,
        "capability_token": c.lease.capability_token,
        "target_status": "cancelling",
    }
    first = authority.transition_run(**command)
    again = authority.transition_run(**command)
    assert first.replayed and again.replayed and first == again
    for drift in ({"fence_token": c.lease.fence_token + 1}, {"target_status": "running"}):
        with pytest.raises(ExecutionControlPlaneError):
            authority.transition_run(**{**command, **drift})


@pytest.mark.asyncio
@pytest.mark.parametrize("ack", [False, True])
async def test_cancellation_needs_exact_physical_stop_before_terminal_release(
    controller_case, ack
):
    c = controller_case
    c.controls.auto_complete = False
    c.controls.stop_ack = ack
    cancellation = asyncio.Event()
    execution = asyncio.create_task(c.executor.execute(c.lease, cancellation=cancellation))
    await asyncio.wait_for(c.prepared.wait(), 2)
    while not c.inputs:
        await asyncio.sleep(0.01)
    cancellation.set()
    assert await execution == ("cancelled" if ack else "orphaned")
    result = await c.executor.prepare_finalization(c.lease, result="cancelled")
    assert result == ("cancelled" if ack else "orphaned")
    if ack:
        await c.executor.finalize(c.lease, result=result)
        assert c.journal.read(c.lease.run_id).process_stopped
    else:
        with pytest.raises(RunnerControlError):
            await c.executor.finalize(c.lease, result=result)
        assert c.lease.run_id in c.executor._active
    assert len(c.inputs) == 1
    assert set(c.stops) == {token_bound_runner_id("x" * 43)}


@pytest.mark.asyncio
async def test_cancel_stops_physical_runner_before_waiting_for_an_inflight_model_request(
    controller_case,
):
    c = controller_case
    c.controls.pause_gateway = True
    cancellation = asyncio.Event()
    execution = asyncio.create_task(c.executor.execute(c.lease, cancellation=cancellation))
    await asyncio.wait_for(c.gateway_started.wait(), 2)
    try:
        await asyncio.wait_for(c.executor.cancel(c.lease), 0.5)
        active = c.executor._active[c.lease.run_id]
        assert active.stopped and active.record.process_stopped and not active.drained
        app = SessionModelChannelMiddleware(FastAPI(), channels=c.channels)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
            denied = await client.post(
                c.physical.channel.base_url + "/responses",
                headers={"Authorization": "Bearer " + c.physical.channel.secret_value},
                json={},
            )
        assert denied.status_code == 503 and len(c.gateway_calls) == 1
    finally:
        c.gateway_release.set()
        cancellation.set()
        outcome = await asyncio.wait_for(execution, 5)
    assert outcome == "cancelled"
    assert await c.executor.prepare_finalization(c.lease, result=outcome) == "cancelled"
    await c.executor.prepare_terminal_transition(c.lease)
    await c.executor.finalize(c.lease, result=outcome)
    assert c.journal.read(c.lease.run_id).process_stopped
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
async def test_concurrent_cancellation_keeps_the_first_exact_stop_acknowledgement(
    controller_case, monkeypatch
):
    c = controller_case
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    stop_calls = []

    async def stop(record):
        ordinal = len(stop_calls) + 1
        stop_calls.append(record.official_runner_id)
        await asyncio.sleep(0.02 * ordinal)
        return ordinal == 1

    monkeypatch.setattr(c.physical, "stop", stop)
    await asyncio.gather(c.executor.cancel(c.lease), c.executor.cancel(c.lease))
    active = c.executor._active[c.lease.run_id]
    assert stop_calls == [active.record.official_runner_id]
    assert active.stopped and active.record.process_stopped
    assert await c.executor.prepare_finalization(c.lease, result="cancelled") == "cancelled"
    await c.executor.finalize(c.lease, result="cancelled")


@pytest.mark.asyncio
async def test_restart_reconciles_original_usage_and_never_dispatches_old_input(controller_case):
    c = controller_case
    c.controls.unknown_fee = True
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    await c.executor.prepare_finalization(c.lease, result="succeeded")
    await c.executor.finalize(c.lease, result="succeeded")
    record = c.journal.read(c.lease.run_id)
    assert list(record.grant.spool_directory.glob("*.pending.json"))
    c.references.available = True
    c.journal.close()
    restored_journal = InteractiveRecoveryJournal(c.journal.root)
    restored = ProductionInteractiveExecutor(
        authorize_model=c.executor._authorize,
        grant_for_run=c.executor._grant,
        driver=c.physical,
        journal=restored_journal,
        recovery_certificate_path=c.certificate.certificate,
        channels=SessionModelChannels(public_origin=ORIGIN),
        connection_generation=c.connection.connection_generation,
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
        assert_authority=lambda: None,
        verify_recovery=c.executor._verify_recovery,
        confirm_recovery=c.executor._confirm_recovery,
        meter_factory=c.executor._meter_factory,
    )
    try:
        assert await restored.reconcile_physical_gc(limit=32) == 1
    finally:
        restored_journal.close()
    assert c.recovered == [c.lease.run_id]
    assert len(c.inputs) == len(c.gateway_calls) == 1
    assert not list(record.grant.spool_directory.glob("*.pending.json"))
    assert all(call["capability_token"] == c.lease.capability_token for call in c.references.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", ("cancelled", "failed"))
async def test_stopped_terminal_without_usage_spool_still_delivers_physical_receipt(
    controller_case, terminal
):
    c = controller_case
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    assert await c.executor.prepare_finalization(c.lease, result=terminal) == terminal
    await c.executor.finalize(c.lease, result=terminal)
    record = c.journal.read(c.lease.run_id)
    assert record.phase == "terminal" and record.process_stopped
    assert not list(record.grant.spool_directory.glob("*.pending.json"))
    stop_count = len(c.stops)
    assert await c.executor.reconcile_physical_gc(limit=32) == 1
    assert c.confirmed == [c.lease.run_id] and len(c.stops) == stop_count
    assert c.journal.read(c.lease.run_id).outcome == terminal
    assert await c.executor.reconcile_physical_gc(limit=32) == 0
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
async def test_successful_idle_runner_without_stop_remains_reusable_and_unconfirmed(
    controller_case,
):
    c = controller_case
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    assert await c.executor.prepare_finalization(c.lease, result="succeeded") == "succeeded"
    await c.executor.finalize(c.lease, result="succeeded")
    assert not c.journal.read(c.lease.run_id).process_stopped
    assert await c.executor.reconcile_physical_gc(limit=32) == 0
    assert not c.confirmed and not c.stops


@pytest.mark.asyncio
async def test_terminal_stop_receipt_retry_retains_proof_without_usage_files(controller_case):
    c = controller_case
    await c.executor.execute(c.lease, cancellation=asyncio.Event())
    await c.executor.prepare_finalization(c.lease, result="cancelled")
    await c.executor.finalize(c.lease, result="cancelled")
    attempts = []

    async def confirm(record):
        attempts.append(physical_recovery_proof_sha256(record))
        if len(attempts) == 1:
            raise RunnerControlError("isolated_stop_receipt_lost_ack", "Unavailable")
        await c.confirm(record)

    c.executor._confirm_recovery = confirm
    with pytest.raises(RunnerControlError):
        await c.executor.reconcile_physical_gc(limit=32)
    retained = c.journal.read(c.lease.run_id)
    assert retained.process_stopped and retained.outcome == "cancelled"
    assert not list(retained.grant.spool_directory.glob("*.pending.json"))
    assert c.lease.run_id not in c.executor._confirmed_recoveries
    stop_count = len(c.stops)
    assert await c.executor.reconcile_physical_gc(limit=32) == 1
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert c.confirmed == [c.lease.run_id] and len(c.stops) == stop_count
    assert await c.executor.reconcile_physical_gc(limit=32) == 0
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
async def test_background_stop_receipt_does_not_hold_the_public_stop_lifecycle(controller_case):
    c = controller_case
    await c.executor.execute(c.lease, cancellation=asyncio.Event())
    await c.executor.prepare_finalization(c.lease, result="cancelled")
    await c.executor.finalize(c.lease, result="cancelled")
    started, finish = asyncio.Event(), asyncio.Event()

    async def confirm(record):
        started.set()
        await finish.wait()
        await c.confirm(record)

    async def cancel_inputs():
        return {"queued": False, "physical_run_id": str(c.lease.run_id)}

    c.executor._confirm_recovery = confirm
    gc = asyncio.create_task(c.executor.reconcile_physical_gc(limit=32))
    stop = None
    try:
        await asyncio.wait_for(started.wait(), 2)
        stop = asyncio.create_task(
            c.executor.stop_session(
                c.context,
                c.authorized.session_id,
                c.journal.read(c.lease.run_id).official_runner_id,
                cancel_inputs,
            )
        )
        assert await asyncio.wait_for(asyncio.shield(stop), 0.5) == {"queued": False}
    finally:
        finish.set()
        await gc
        if stop is not None:
            await stop


@pytest.mark.asyncio
async def test_recovery_receipt_follows_physical_ack_and_retains_pending_confirmation(
    controller_case,
):
    c = controller_case
    await c.executor.execute(c.lease, cancellation=asyncio.Event())
    await c.executor.prepare_finalization(c.lease, result="succeeded")
    active = c.executor._active.pop(c.lease.run_id)
    active.meter.close(timeout_seconds=0)
    c.controls.stop_ack = False
    assert await c.executor.reconcile_physical_gc(limit=32) == 0
    assert not c.confirmed
    with pytest.raises(InteractiveRecoveryError):
        physical_recovery_proof_sha256(c.journal.read(c.lease.run_id))
    c.controls.stop_ack = True

    async def pending_confirmation(record):
        assert record.process_stopped
        assert len(physical_recovery_proof_sha256(record)) == 64
        raise RunnerControlError("interactive_controller_recovery_pending", "Unavailable")

    c.executor._confirm_recovery = pending_confirmation
    with pytest.raises(RunnerControlError):
        await c.executor.reconcile_physical_gc(limit=32)
    pending = c.journal.read(c.lease.run_id)
    assert pending.process_stopped and pending.phase != "terminal"
    assert c.lease.run_id not in c.executor._confirmed_recoveries
    stop_count = len(c.stops)
    c.executor._confirm_recovery = c.confirm
    assert await c.executor.reconcile_physical_gc(limit=32) == 1
    assert len(c.stops) == stop_count and c.confirmed == [c.lease.run_id]
    done = c.journal.read(c.lease.run_id)
    assert done.phase == "terminal" and done.outcome == "orphaned"
    assert c.lease.run_id in c.executor._confirmed_recoveries
    assert await c.executor.reconcile_physical_gc(limit=32) == 0
    assert len(c.inputs) == len(c.gateway_calls) == 1


def test_http_creation_persists_only_frozen_model_channel_references(interactive_http):
    f = interactive_http
    f.store._public_origin = ORIGIN
    body = _managed_create(f)
    result = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert result.status_code == 201, result.text
    from saas.compatibility import bind_runtime_context

    with bind_runtime_context(f.runtime):
        conversation = f.delegate.get_conversation(result.json()["id"])
    configuration = conversation.inference_snapshot["runtime_config"]
    api = configuration["providers"]["platform-deepseek"]["openai"]
    expected = interactive_session_identity(
        f.runtime.tenant_id, f.runtime.space_id, f.runtime.runtime_partition_id, conversation.id
    )
    assert api["base_url"] == ORIGIN + f"/internal/v1/model-channels/{expected}/v1"
    assert api["api_key_ref"] == "env:OMNIGENT_PLATFORM_DEEPSEEK_KEY"
    assert "api_key" not in api and "deployment_alias" not in json.dumps(configuration)
    assert (
        configuration["inference"]["harnesses"]["openai-agents"]["default_model"]
        == f.marker["public_model_id"]
    )
    replay = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert replay.status_code == 201 and replay.json()["id"] == conversation.id


def test_browser_cannot_spoof_native_controller_completion(interactive_http):
    from omnigent.runner.identity import RUNNER_TUNNEL_TOKEN_HEADER, RUNNER_TUNNEL_WORKSPACE_HEADER
    from saas.compatibility import bind_runtime_context

    f = interactive_http
    token = "y" * 43
    with bind_runtime_context(f.runtime):
        f.delegate.replace_runner_id(f.conversation.id, token_bound_runner_id(token))
    observed = []
    f.store.runtime_status_observer = lambda _conversation, data: observed.append(data)
    route = f"/v1/sessions/{f.conversation.id}/events"
    body = {
        "type": "external_session_status",
        "data": {"status": "idle", "response_id": "codex-current", "turn_completed": True},
    }
    browser = f.client.post(route, json=body, headers=f.headers)
    assert browser.status_code == 202 and not observed
    delegated = {
        **f.headers,
        RUNNER_TUNNEL_TOKEN_HEADER: token,
        RUNNER_TUNNEL_WORKSPACE_HEADER: str(f.runtime.physical_workspace_id),
    }
    runner = f.client.post(route, json=body, headers=delegated)
    assert runner.status_code == 202, runner.text
    assert len(observed) == 1
    interrupted = f.client.post(
        route,
        json={"type": "external_session_interrupted", "data": {"response_id": "codex-current"}},
        headers=delegated,
    )
    assert interrupted.status_code == 202 and observed[-1]["interrupted"] is True


@pytest.mark.asyncio
async def test_recovery_cannot_rebind_a_rotated_certificate(controller_case):
    c = controller_case
    c.controls.unknown_fee = True
    await c.executor.execute(c.lease, cancellation=asyncio.Event())
    await c.executor.prepare_finalization(c.lease, result="succeeded")
    await c.executor.finalize(c.lease, result="succeeded")
    record = c.journal.read(c.lease.run_id)
    record.grant.client_certificate_path.write_bytes(b"different-isolated-certificate")
    with pytest.raises(RunnerControlError):
        await c.executor.reconcile_physical_gc(limit=32)
    assert list(record.grant.spool_directory.glob("*.pending.json"))


@pytest.mark.asyncio
async def test_owner_only_journal_is_locked_and_original_grant_is_immutable(controller_case):
    c = controller_case
    await c.executor.execute(c.lease, cancellation=asyncio.Event())
    record = c.journal.read(c.lease.run_id)
    assert record == c.executor._active[c.lease.run_id].record
    assert (c.journal.root / f"{record.run_id}.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(InteractiveRecoveryError):
        InteractiveRecoveryJournal(c.journal.root)
    with pytest.raises(InteractiveRecoveryError):
        c.journal.put(
            replace(
                record, grant=replace(record.grant, capability_token="foreign-original-capability")
            )
        )
    path = c.journal.root / f"{record.run_id}.json"
    path.chmod(0o644)
    with pytest.raises(InteractiveRecoveryError):
        c.journal.read(record.run_id)
    path.chmod(0o600)


@pytest.mark.asyncio
async def test_corrupt_recovery_metadata_fails_closed_without_exposing_the_original_grant(
    controller_case,
):
    c = controller_case
    await c.executor.execute(c.lease, cancellation=asyncio.Event())
    path = c.journal.root / f"{c.lease.run_id}.json"
    original = path.read_text()
    for field, value in (("image_digest", False), ("process_stopped", "yes"), ("grant", 42)):
        document = json.loads(original)
        document["record"][field] = value
        path.write_text(json.dumps(document))
        with pytest.raises(InteractiveRecoveryError) as error:
            c.journal.read(c.lease.run_id)
        assert c.lease.capability_token not in str(error.value)
    path.write_text(original)


def test_controller_factory_is_closed_without_an_explicit_deployment_flag(monkeypatch):
    from saas.production.interactive_controller_adapter import (
        build_production_interactive_controller,
    )

    monkeypatch.delenv("OMNIGENT_SAAS_INTERACTIVE_CONTROLLER_ENABLED", raising=False)
    with pytest.raises(RunnerControlError):
        build_production_interactive_controller(config=object())


@pytest.mark.asyncio
async def test_binding_and_lifespan_readiness_are_distinct_from_dependency_preflight():
    from saas.production.interactive_controller_adapter import (
        ProductionInteractiveControllerAdapter,
    )

    adapter = object.__new__(ProductionInteractiveControllerAdapter)
    checks = []
    adapter._readiness = SimpleNamespace(
        assert_production_ready=lambda: checks.append("dependency")
    )
    adapter._installed = False
    adapter.assert_production_ready()
    assert checks == ["dependency"]
    adapter._installed, adapter._bound = True, False
    with pytest.raises(RunnerControlError):
        adapter.assert_production_ready()
    adapter._bound = True
    adapter._task = asyncio.get_running_loop().create_future()
    adapter._executor = SimpleNamespace(assert_production_ready=lambda: checks.append("executor"))
    adapter.assert_production_ready()
    assert checks[-1] == "executor"
    adapter._task.set_result(None)
    with pytest.raises(RunnerControlError):
        adapter.assert_production_ready()


@pytest.mark.asyncio
async def test_stop_uses_live_controller_not_spare_admission_capacity():
    from saas.production.interactive_controller_adapter import (
        ProductionInteractiveControllerAdapter,
    )

    adapter = object.__new__(ProductionInteractiveControllerAdapter)
    calls = []

    def no_capacity():
        pytest.fail("Stopping cannot require a spare Runner slot")

    async def stop(*args):
        calls.append(args)
        return {"queued": False}

    adapter._readiness = SimpleNamespace(assert_production_ready=no_capacity)
    adapter._bound = True
    adapter._task = asyncio.get_running_loop().create_future()
    adapter._executor = SimpleNamespace(stop_session=stop)
    conversation = SimpleNamespace(id="a" * 32, runner_id="owned-runner")
    assert await adapter.stop_session(conversation, "context", "cancel") == {"queued": False}
    assert calls == [("context", conversation.id, conversation.runner_id, "cancel")]
    adapter._task.set_result(None)
    with pytest.raises(RunnerControlError):
        await adapter.stop_session(conversation, "context", "cancel")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_terminal_observation_requires_current_response_not_idle_or_foreign_turn():
    observation = InteractiveTurnObservation(asyncio.get_running_loop().create_future())
    observation.sdk({"type": "response.completed", "response": {"id": "old"}})
    observation.armed = True
    observation.native({"status": "idle", "response_id": "old"}, harness="codex-native")
    assert not observation.future.done()
    observation.sdk({"type": "response.in_progress", "response": {"id": "current"}})
    observation.sdk({"type": "response.completed", "response": {"id": "old"}})
    assert not observation.future.done()
    observation.sdk({"type": "response.completed", "response": {"id": "current"}})
    assert await observation.future == "succeeded"


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupted", [False, True])
async def test_codex_native_interrupt_is_not_misreported_by_following_idle(interrupted):
    observation = InteractiveTurnObservation(
        asyncio.get_running_loop().create_future(), armed=True
    )
    observation.native({"status": "running", "response_id": "codex-turn"}, harness="codex-native")
    if interrupted:
        observation.native(
            {"interrupted": True, "response_id": "codex-turn"}, harness="codex-native"
        )
    observation.native({"status": "idle", "response_id": "codex-turn"}, harness="codex-native")
    assert await observation.future == ("cancelled" if interrupted else "succeeded")


@pytest.mark.asyncio
async def test_quiescence_idle_for_an_unconfirmed_native_harness_is_not_completion():
    observation = InteractiveTurnObservation(
        asyncio.get_running_loop().create_future(), armed=True
    )
    observation.native({"status": "running", "response_id": "claude-turn"})
    observation.native({"status": "idle", "response_id": "claude-turn"})
    assert not observation.future.done()
    observation.native({"status": "idle", "response_id": "claude-turn", "turn_completed": True})
    assert await observation.future == "succeeded"
