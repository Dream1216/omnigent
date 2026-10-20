"""Control-plane release, UID guards, and retained cleanup worker contracts."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from saas.control_plane.scheduling_models import RunDispatchRecord
from saas.production.interactive_driver import OfficialInteractiveDriver
from saas.production.interactive_managed_lifecycle import (
    ControlledManagedLauncher,
    protect_managed_deployment,
)
from saas.production.interactive_preparation import _direct_launcher
from saas.production.interactive_recovery import ManagedPodTermination, ManagedTerminationReceipt
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_resources import _case, _resources
from tests.saas.test_interactive_managed_termination_records import _intent, _record
from tests.saas.test_interactive_orphaned_retirement import _release, _terminal, _trusted_recovery


async def _stranded(c):
    active = await _record(c)
    for intent in (
        _intent(),
        _intent(secret_submitted=True),
        _intent(secret_submitted=True, secret_uid=str(UUID(int=2))),
        _intent(
            secret_submitted=True,
            secret_uid=str(UUID(int=2)),
            workload_submitted=True,
            input_template_sha256="a" * 64,
        ),
    ):
        c.executor._put(active, managed_creation=intent)
    c.executor._put(active, managed_resources=_resources())
    c.executor._put(active, phase="draining", outcome="orphaned")
    c.executor._active.pop(c.lease.run_id).meter.close(timeout_seconds=0)
    _trusted_recovery(c)
    return c.journal.read(c.lease.run_id)


@pytest.mark.asyncio
async def test_cleanup_requires_trusted_release_and_complete_receipt_before_confirmation(
    controller_case,
):
    c = controller_case
    await _stranded(c)
    calls = []
    complete = False

    async def recover(record, checkpoint):
        calls.append(record.run_id)
        pod = ManagedPodTermination(str(UUID(int=3)), "owned-pod", "d" * 64 if complete else None)
        return await checkpoint(
            managed_termination=ManagedTerminationReceipt(
                pods=(pod,),
                secret_uid=str(UUID(int=2)),
                secret_gone=complete,
                quiescence_sha256="e" * 64,
                complete=complete,
            )
        )

    c.physical.recover_managed = recover
    assert await c.executor.reconcile_physical_gc(limit=10) == 0
    _terminal(c)
    assert await c.executor.reconcile_physical_gc(limit=10) == 0
    assert not calls
    _release(c)
    assert await c.executor.reconcile_physical_gc(limit=10) == 0
    assert calls == [c.lease.run_id] and not c.confirmed
    with c.f.factory() as db:
        assert db.get(RunDispatchRecord, c.lease.run_id).physical_recovery_fence is None
    complete = True
    assert await c.executor.reconcile_physical_gc(limit=10) == 1
    record = c.journal.read(c.lease.run_id)
    assert record.stop_kind == "managed_container" and record.process_stopped
    assert record.phase == "terminal" and record.outcome == "orphaned"
    assert c.confirmed == [c.lease.run_id]
    with c.f.factory() as db:
        assert (
            db.get(RunDispatchRecord, c.lease.run_id).physical_recovery_fence
            == c.lease.fence_token
        )


@pytest.mark.asyncio
async def test_active_peer_on_same_managed_host_prevents_cleanup(controller_case):
    c = controller_case
    record = await _stranded(c)
    peer_id = uuid4()
    c.journal.put(
        replace(
            record,
            run_id=peer_id,
            grant=replace(record.grant, run_id=peer_id),
            managed_creation=None,
            managed_resources=None,
            managed_preparation=None,
            phase="preparing",
            outcome=None,
            host_id=record.managed_preparation.host_id,
        )
    )
    _terminal(c)
    _release(c)

    async def forbidden(*_args):
        pytest.fail("a shared Host with a nonterminal peer cannot be stopped")

    c.physical.recover_managed = forbidden
    assert await c.executor._recover_unknown_managed(record) is False
    assert not c.confirmed and not c.journal.read(c.lease.run_id).process_stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["start_host", "terminate", "resume", "suspend"])
async def test_global_legacy_writer_is_fenced_but_scoped_factory_unwraps(
    tmp_path, monkeypatch, action
):
    c = _case(tmp_path, monkeypatch)
    journal = SimpleNamespace(records=list)
    protect_managed_deployment(c.p.deployment, journal)
    wrapper = c.p.deployment.default.launcher_factory()
    assert type(wrapper) is ControlledManagedLauncher
    before = c.p.trace.copy()
    with pytest.raises(RunnerControlError):
        getattr(wrapper, action)("owned-job")
    assert _direct_launcher(c.p.deployment.default, "kubernetes") is c.p.delegate
    assert c.p.trace == before


@pytest.mark.asyncio
async def test_keepalive_is_uid_bound_and_cannot_race_a_recorded_stop(tmp_path, monkeypatch):
    c = _case(tmp_path, monkeypatch, "agent_sandbox")
    await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    record = SimpleNamespace(
        run_id=uuid4(),
        managed_preparation=c.p.recorded[0],
        managed_creation=c.intents[-1],
        managed_resources=c.resources[0],
        managed_termination=None,
        managed_suspension=None,
        managed_predecessor_run_id=None,
    )
    journal = SimpleNamespace(records=lambda: [record], read=lambda _id: record)
    c.workload["metadata"]["resourceVersion"] = "opaque-keepalive-rv"
    calls = []
    c.p.delegate._api_client.call_api = lambda *args, **kwargs: calls.append((args, kwargs))
    guard = ControlledManagedLauncher(c.p.delegate, journal)
    assert guard.keep_alive("owned-job")
    assert len(calls) == 1
    assert calls[0][1]["body"][:2] == [
        {"op": "test", "path": "/metadata/uid", "value": c.resources[0].workload_uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "opaque-keepalive-rv"},
    ]
    record.managed_termination = ManagedTerminationReceipt()
    assert guard.keep_alive("owned-job") is False and len(calls) == 1


@pytest.mark.asyncio
async def test_cancelled_observer_retains_one_cleanup_task_without_replaying(
    controller_case, monkeypatch
):
    from saas.production import interactive_managed_recovery as module

    started, release = asyncio.Event(), asyncio.Event()
    calls = []
    record = SimpleNamespace(run_id=uuid4(), runtime=controller_case.context, managed_resume=False)

    async def recover(*args):
        calls.append(args)
        started.set()
        await release.wait()
        return record

    monkeypatch.setattr(module, "recover_managed_resources", recover)
    driver = OfficialInteractiveDriver(
        app=SimpleNamespace(state=SimpleNamespace(sandbox_config=object())),
        dependencies=object(),
        contract_version="0.2.0",
    )
    first = asyncio.create_task(driver.recover_managed(record, object()))
    second = None
    try:
        await asyncio.wait_for(started.wait(), timeout=5)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert len(driver._managed_recoveries) == 1
        second = asyncio.create_task(driver.recover_managed(record, object()))
        await asyncio.sleep(0)
        release.set()
        assert await second is record and len(calls) == 1
        assert not driver._managed_recoveries
    finally:
        release.set()
        await asyncio.gather(first, *(() if second is None else (second,)), return_exceptions=True)
