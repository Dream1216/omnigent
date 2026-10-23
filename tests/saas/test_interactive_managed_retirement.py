"""Controller/real HostStore ordering; provider receipts are constructed, not live Pod proof."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.db_models import SqlHost, current_workspace_id
from omnigent.db.utils import now_epoch
from omnigent.stores.host_store import HostStore, hash_host_launch_token
from saas.compatibility import OmnigentStoreAdapter
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.production.interactive_driver import OfficialInteractiveDriver
from saas.production.interactive_managed_retirement import ControllerManagedSandboxReaper
from saas.production.interactive_recovery import (
    ManagedPodTermination,
    ManagedTerminationReceipt,
    physical_recovery_proof_sha256,
)
from saas.production.runner_control import RunnerControlError
from tests.saas import test_interactive_managed_reuse as warm
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_orphaned_retirement import _machine
from tests.server.test_managed_sandbox_reaper import _deployment, _RecordingLauncher


async def _case(c, db_uri, monkeypatch, *, provider="kubernetes"):
    token = "fixture-managed-launch-token"
    digest = hash_host_launch_token(token)
    intent, resources = warm._intent, warm._resources
    monkeypatch.setattr(
        warm, "_intent", lambda **kw: intent(**{"host_token_sha256": digest, **kw})
    )
    monkeypatch.setattr(
        warm, "_resources", lambda **kw: resources(**{"host_token_sha256": digest, **kw})
    )
    w = await warm._warm(c, provider=provider)
    store, adapter = HostStore(db_uri), OmnigentStoreAdapter("0.2.0")
    binding, current = w.root.managed_preparation, now_epoch()
    with adapter.bind(c.context):
        host = store.register_managed_host(
            host_id=binding.host_id,
            name="fixture-owned-host",
            user_id=c.context.runtime_user_key,
            token=token,
            provider=provider,
            sandbox_id=binding.resource_name,
            token_expires_at=current + 10 * 86400,
        )
    deployment = _deployment([_RecordingLauncher(provider)], terminate_after_offline_days=7)
    app = SimpleNamespace(state=SimpleNamespace(sandbox_config=deployment))
    driver = OfficialInteractiveDriver(
        app=app, dependencies=SimpleNamespace(host_store=store), contract_version="0.2.0"
    )
    trace, calls = [], []
    stage = SimpleNamespace(fail=False, drift=False, pause=False)
    entered, resume = asyncio.Event(), asyncio.Event()

    def inspect(_deployment, record):
        assert record.run_id == w.root.run_id
        trace.append("read-resources")
        if stage.drift:
            raise RunnerControlError("interactive_controller_unavailable", "Unavailable")
        return record.managed_resources

    monkeypatch.setattr(
        "saas.production.interactive_preparation.inspect_managed_resources", inspect
    )
    for name in (
        "inspect_managed_retirement",
        "detach_managed_retirement",
        "finish_managed_retirement",
    ):
        setattr(c.physical, name, getattr(driver, name))

    def args(record):
        return {
            **_machine(c),
            "run_id": record.run_id,
            "fence_token": record.fence_token,
            "capability_token": record.grant.capability_token,
        }

    async def released(record):
        SchedulingControlPlane(c.f.factory).inspect_interactive_recovery(**args(record))

    async def confirm(record):
        assert record.process_stopped
        assert c.journal.read(w.root.run_id).managed_termination.complete
        SchedulingControlPlane(c.f.factory).confirm_interactive_recovery(
            **args(record),
            proof_sha256=physical_recovery_proof_sha256(record),
            certificate_fingerprint_sha256="a" * 64,
            cleanup_kind="physical_stop",
        )
        trace.append("confirm")
        c.confirmed.append(record.run_id)

    c.executor._verify_released, c.executor._confirm_recovery = released, confirm

    async def retire(record, checkpoint):
        snapshot = await checkpoint()
        assert snapshot.managed_termination is not None
        with adapter.bind(c.context):
            pending = store.get_host(binding.host_id, include_deleted=True)
            assert pending.deleted_at is not None or (
                pending.sandbox_id is None
                and pending.terminating_sandbox_id == binding.resource_name
            )
            assert store.resolve_launch_token(binding.host_id, token) is None
        assert not c.confirmed
        calls.append(record.run_id)
        trace.append("sdk-stop")
        if stage.pause:
            entered.set()
            await resume.wait()
        if stage.fail:
            raise RunnerControlError("interactive_controller_unavailable", "Unavailable")
        return await checkpoint(
            managed_termination=ManagedTerminationReceipt(
                secret_uid=record.managed_creation.secret_uid,
                secret_gone=True,
                pods=(ManagedPodTermination(str(UUID(int=3)), "owned-pod", "c" * 64),),
                quiescence_sha256="d" * 64,
                complete=True,
            )
        )

    c.physical.retire_managed = retire
    reaper = ControllerManagedSandboxReaper(
        executor=c.executor, driver=driver, host_store=store, sandbox_config=deployment
    )
    return SimpleNamespace(**locals())


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
async def test_stale_owned_generation_retires_after_receipt_without_task_replay(
    controller_case, db_uri, monkeypatch, provider
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch, provider=provider)
    assert await r.reaper.sweep_once(now=r.current) == 0
    assert r.trace == []
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 1
    with r.adapter.bind(c.context):
        host = r.store.get_host(r.binding.host_id)
        assert host.sandbox_id is host.terminating_sandbox_id is None
    root = c.journal.read(r.w.root.run_id)
    assert root.process_stopped and root.managed_termination.complete
    assert r.trace == ["read-resources", "sdk-stop", "confirm"]
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 0
    assert len(c.inputs) == len(c.gateway_calls) == len(r.calls) == 1


@pytest.mark.asyncio
async def test_pending_warm_reference_blocks_detach_and_token_revocation(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    second = await r.w.next_lease()
    active, _ = await c.executor._prepare_active(second, cancellation=asyncio.Event())
    c.executor._put(active, managed_origin_run_id=r.w.root.run_id)
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 0
    with r.adapter.bind(c.context):
        assert r.store.get_host(r.binding.host_id).sandbox_id == r.binding.resource_name
        assert r.store.resolve_launch_token(r.binding.host_id, r.token) is not None
    assert not r.trace and not c.confirmed


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["credential", "resource"])
async def test_generation_drift_cannot_detach_or_persist_stop_intent(
    controller_case, db_uri, monkeypatch, drift
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    if drift == "resource":
        r.stage.drift = True
    else:
        with Session(r.store._engine) as db:
            db.execute(
                sa.update(SqlHost)
                .where(
                    SqlHost.workspace_id == c.context.physical_workspace_id,
                    SqlHost.host_id == r.binding.host_id,
                )
                .values(token_hash=hash_host_launch_token("new-fixture-token"))
            )
            db.commit()
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 0
    with r.adapter.bind(c.context):
        host = r.store.get_host(r.binding.host_id)
        assert host.sandbox_id == r.binding.resource_name and host.terminating_sandbox_id is None
    assert c.journal.read(r.w.root.run_id).managed_termination is None
    assert not r.calls and not c.confirmed


@pytest.mark.asyncio
async def test_partial_retirement_resumes_cleanup_not_the_input(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    r.stage.fail = True
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 0
    root = c.journal.read(r.w.root.run_id)
    assert root.managed_termination is not None and not root.process_stopped
    assert not c.confirmed
    r.stage.fail = False
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 1
    assert len(r.calls) == 2 and len(c.inputs) == len(c.gateway_calls) == 1


async def _orphaned_peer(c, r):
    second = await r.w.next_lease()
    active, _ = await c.executor._prepare_active(second, cancellation=asyncio.Event())
    c.executor._put(active, managed_origin_run_id=r.w.root.run_id)
    c.executor._put(
        active,
        phase="draining",
        outcome="orphaned",
        host_id=None,
        official_runner_id=None,
        host_owner=None,
        host_account_generation=None,
    )
    for action in ("transition_run", "release_run"):
        args = {**r.w.machine, "run_id": second.run_id, "fence_token": second.fence_token}
        if action == "transition_run":
            args.update(
                lease_token=second.lease_token,
                capability_token=second.capability_token,
                target_status="orphaned",
            )
        getattr(r.w.control, action)(**args)
    active.finished.set()
    return second, active


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
async def test_released_unknown_warm_peer_uses_its_own_fence_and_origin_stop(
    controller_case, db_uri, monkeypatch, provider
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch, provider=provider)
    second, _ = await _orphaned_peer(c, r)
    assert await c.executor.reconcile_physical_gc(limit=5) >= 1
    peer = c.journal.read(second.run_id)
    assert peer.phase == "terminal" and peer.process_stopped and peer.stop_kind == "managed_origin"
    assert peer.managed_origin_run_id == r.w.root.run_id
    assert (
        peer.grant.run_id == second.run_id
        and peer.grant.capability_token == second.capability_token
    )
    assert set(c.confirmed) == {r.w.root.run_id, second.run_id}
    assert len(c.inputs) == len(c.gateway_calls) == len(r.calls) == 1


@pytest.mark.asyncio
async def test_physical_stop_retains_the_original_grant_while_channel_drain_is_pending(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    second, active = await _orphaned_peer(c, r)
    grant, seal, held = active.record.grant, c.executor._seal, SimpleNamespace(value=True)

    async def draining(current, **kwargs):
        if current is active and held.value:
            current.drained = False
            return False
        return await seal(current, **kwargs)

    c.executor._seal = draining
    assert await c.executor.reconcile_physical_gc(limit=5) >= 1
    peer = c.journal.read(second.run_id)
    assert peer.process_stopped and peer.grant == grant
    assert c.executor._active[second.run_id].record == peer
    with r.adapter.bind(c.context):
        assert r.store.get_host(r.binding.host_id).terminating_sandbox_id is None
    held.value = False
    await c.executor.reconcile_physical_gc(limit=5)
    assert second.run_id not in c.executor._active
    assert len(c.inputs) == len(c.gateway_calls) == len(r.calls) == 1


@pytest.mark.asyncio
async def test_normal_retirement_keeps_a_previously_confirmed_runner_proof_unchanged(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    acknowledged = replace(r.w.root, process_stopped=True)
    c.journal.put(acknowledged)
    before = physical_recovery_proof_sha256(acknowledged)
    SchedulingControlPlane(c.f.factory).confirm_interactive_recovery(
        **r.args(acknowledged),
        proof_sha256=before,
        certificate_fingerprint_sha256="a" * 64,
        cleanup_kind="physical_stop",
    )
    c.executor._confirmed_recoveries.add(acknowledged.run_id)
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 1
    assert physical_recovery_proof_sha256(c.journal.read(acknowledged.run_id)) == before
    assert not c.confirmed and len(r.calls) == 1


@pytest.mark.asyncio
async def test_cancelled_retirement_waiter_cannot_duplicate_the_stop(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    r.stage.pause = True
    first = asyncio.create_task(r.reaper.sweep_once(now=r.current + 8 * 86400))
    second = None
    try:
        await asyncio.wait_for(r.entered.wait(), 3)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        second = asyncio.create_task(r.reaper.sweep_once(now=r.current + 8 * 86400))
        r.resume.set()
        assert await asyncio.wait_for(second, 5) == 1
        assert len(r.calls) == 1
    finally:
        r.resume.set()
        for task in (first, second):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (first, second) if task is not None), return_exceptions=True
        )


@pytest.mark.asyncio
async def test_heartbeat_snapshot_loser_leaves_no_private_stop_intent(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    detach = c.physical.detach_managed_retirement

    async def refreshed(record, expected):
        with Session(r.store._engine) as db:
            db.execute(
                sa.update(SqlHost)
                .where(
                    SqlHost.workspace_id == c.context.physical_workspace_id,
                    SqlHost.host_id == r.binding.host_id,
                )
                .values(updated_at=expected.updated_at + 1)
            )
            db.commit()
        return await detach(record, expected)

    c.physical.detach_managed_retirement = refreshed
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 0
    assert c.journal.read(r.w.root.run_id).managed_termination is None
    with r.adapter.bind(c.context):
        assert r.store.resolve_launch_token(r.binding.host_id, r.token) is not None
    assert not r.calls and not c.confirmed


@pytest.mark.asyncio
async def test_deleted_host_tombstone_clears_only_after_the_resource_receipt(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    with r.adapter.bind(c.context):
        r.store.delete_host(r.binding.host_id)
        assert r.store.get_host(r.binding.host_id) is None
        assert r.store.get_host(r.binding.host_id, include_deleted=True) is not None
    assert await r.reaper.sweep_once(now=r.current) == 1
    with r.adapter.bind(c.context):
        assert r.store.get_host(r.binding.host_id, include_deleted=True) is None
    assert c.journal.read(r.w.root.run_id).managed_termination.complete


@pytest.mark.asyncio
async def test_sdk_retirement_uses_the_original_runtime_context(
    controller_case, db_uri, monkeypatch
):
    c = controller_case
    r = await _case(c, db_uri, monkeypatch)
    outside = current_workspace_id()
    assert outside != c.context.physical_workspace_id

    async def actual_scope(deployment, record, checkpoint):
        assert deployment is r.deployment and record == r.w.root
        assert current_workspace_id() == c.context.physical_workspace_id
        return record

    monkeypatch.setattr(
        "saas.production.interactive_managed_recovery.retire_managed_resources", actual_scope
    )
    assert await r.driver.retire_managed(r.w.root, None) == r.w.root
    assert current_workspace_id() == outside
