"""Logical release never substitutes for a physical stop or a trusted recovery receipt."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.scheduling import SchedulingControlPlane, SchedulingError
from saas.control_plane.scheduling_models import RunDispatchRecord
from saas.production.interactive_recovery import physical_recovery_proof_sha256
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http


def _machine(c):
    return {
        "runner_id": c.connection.runner_id,
        "connection_generation": c.connection.connection_generation,
        "connection_token": c.connection.connection_token,
        "run_id": c.lease.run_id,
        "fence_token": c.lease.fence_token,
        "capability_token": c.lease.capability_token,
        "expected_product_revision": "c" * 40,
        "product_image_digest": "sha256:" + "a" * 64,
    }


def _terminal(c):
    ExecutionControlPlane(c.f.factory).transition_run(
        run_id=c.lease.run_id,
        lease_token=c.lease.lease_token,
        fence_token=c.lease.fence_token,
        target_status="orphaned",
        trace_id="isolated-orphaned-retirement",
        now=c.lease.expires_at - timedelta(seconds=1),
    )


def _release(c):
    SchedulingControlPlane(c.f.factory).release_dispatch(
        run_id=c.lease.run_id,
        runner_id=c.connection.runner_id,
        connection_generation=c.connection.connection_generation,
        connection_token=c.connection.connection_token,
        fence_token=c.lease.fence_token,
        requeue=False,
        now=c.lease.expires_at - timedelta(seconds=1),
    )


def _trusted_recovery(c, **drift):
    async def released(record):
        args = {
            **_machine(c),
            "fence_token": record.fence_token,
            "capability_token": record.grant.capability_token,
            **drift,
        }
        try:
            SchedulingControlPlane(c.f.factory).inspect_interactive_recovery(**args)
        except SchedulingError as error:
            raise RunnerControlError(error.code, "Recovery unavailable") from None

    async def confirm(record):
        SchedulingControlPlane(c.f.factory).confirm_interactive_recovery(
            **_machine(c),
            proof_sha256=physical_recovery_proof_sha256(record),
            certificate_fingerprint_sha256="a" * 64,
            cleanup_kind="physical_stop",
        )
        c.confirmed.append(record.run_id)

    c.executor._verify_released = released
    c.executor._confirm_recovery = confirm


async def _pending(c):
    c.controls.stop_ack = False

    async def outcome(*args):
        return "failed"

    c.physical.outcome = outcome
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "failed"
    assert await c.executor.prepare_finalization(c.lease, result="failed") == "orphaned"
    await c.executor.finalize(c.lease, result="orphaned")
    active = c.executor._active[c.lease.run_id]
    assert active.finished.is_set() and not active.record.process_stopped
    assert active.record.phase == "draining" and active.record.outcome == "orphaned"
    with pytest.raises(RunnerControlError) as pending:
        c.executor.assert_claimable()
    assert pending.value.code == "interactive_controller_recovery_pending"
    return active


@pytest.mark.asyncio
async def test_orphaned_retirement_requires_released_dispatch_and_real_stop(controller_case):
    c = controller_case
    _trusted_recovery(c)
    await _pending(c)
    for step in (lambda: None, lambda: _terminal(c)):
        step()
        before = len(c.stops)
        assert await c.executor.reconcile_physical_gc(limit=10) == 0
        assert c.lease.run_id in c.executor._active
        assert len(c.stops) == before and not c.confirmed
    _release(c)
    assert await c.executor.reconcile_physical_gc(limit=10) == 0
    assert c.lease.run_id not in c.executor._active
    assert not c.journal.read(c.lease.run_id).process_stopped
    with c.f.factory() as db:
        assert db.get(RunDispatchRecord, c.lease.run_id).physical_recovery_fence is None
    with pytest.raises(RunnerControlError):
        c.executor.assert_claimable()
    c.controls.stop_ack = True
    assert await c.executor.reconcile_physical_gc(limit=10) == 1
    record = c.journal.read(c.lease.run_id)
    assert record.process_stopped and record.phase == "terminal" and record.outcome == "orphaned"
    with c.f.factory() as db:
        assert (
            db.get(RunDispatchRecord, c.lease.run_id).physical_recovery_fence
            == c.lease.fence_token
        )
    c.executor.assert_claimable()
    assert c.confirmed == [c.lease.run_id]
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "barrier", ["no_verifier", "executing", "preparation", "dispatching", "quiesce", "drain"]
)
async def test_orphaned_retirement_retains_unresolved_local_barriers(controller_case, barrier):
    c = controller_case
    _trusted_recovery(c)
    active = await _pending(c)
    _terminal(c)
    _release(c)
    task = None
    if barrier == "no_verifier":
        c.executor._verify_released = None
    elif barrier == "executing":
        active.executing = True
    elif barrier in {"preparation", "dispatching"}:
        task = asyncio.create_task(asyncio.Event().wait())
        setattr(active, barrier, task)
    elif barrier == "quiesce":

        async def quiesce(*args):
            raise RunnerControlError("interactive_preparation_pending", "Unavailable")

        c.physical.quiesce_preparation = quiesce
    else:

        async def seal(*args, **kwargs):
            return False

        c.executor._seal = seal
    before = len(c.stops)
    try:
        try:
            assert await c.executor.reconcile_physical_gc(limit=10) == 0
        except RunnerControlError:
            assert barrier == "quiesce"
        assert c.executor._active[c.lease.run_id] is active
        assert not active.record.process_stopped and not c.confirmed
        assert len(c.stops) == before
    finally:
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift",
    [
        {"fence_token": 9999},
        {"capability_token": "wrong"},
        {"expected_product_revision": "d" * 40},
    ],
)
async def test_orphaned_retirement_rejects_untrusted_release_binding(controller_case, drift):
    c = controller_case
    _trusted_recovery(c, **drift)
    active = await _pending(c)
    _terminal(c)
    _release(c)
    with pytest.raises(RunnerControlError) as rejected:
        await c.executor.reconcile_physical_gc(limit=10)
    assert rejected.value.code == "interactive_recovery_binding_invalid"
    assert c.executor._active[c.lease.run_id] is active and not c.confirmed


@pytest.mark.asyncio
async def test_finished_orphaned_session_stop_does_not_spin(controller_case):
    c = controller_case
    await _pending(c)

    async def cancel_inputs():
        return {"queued": False}

    with pytest.raises(RunnerControlError):
        await asyncio.wait_for(
            c.executor.stop_session(c.context, c.authorized.session_id, None, cancel_inputs), 1
        )
