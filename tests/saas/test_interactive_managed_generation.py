"""Real HostStore/controller, constructed receipts and SDK responses; not live resume proof."""

from __future__ import annotations

import asyncio
import json
import traceback
from dataclasses import fields, replace
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import httpx
import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from sqlalchemy.orm import Session

from omnigent.db.db_models import SqlHost, current_workspace_id
from omnigent.db.utils import now_epoch
from omnigent.server.managed_hosts import ManagedLaunchTracker
from saas.production.interactive_managed_generation import (
    ManagedGenerationAdmission,
    RetiredGenerationHostStore,
)
from saas.production.interactive_model_channel import SessionModelChannelMiddleware
from saas.production.interactive_preparation import _binding
from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    ManagedCreationIntent,
    ManagedPodTermination,
    ManagedResourceBinding,
    ManagedTerminationReceipt,
    _decode,
    _encode,
    managed_retirement_proof_sha256,
)
from saas.production.runner_control import RunnerControlClientLease, RunnerControlError
from tests.saas import test_interactive_managed_reuse as warm
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_preparation import _launcher
from tests.saas.test_interactive_managed_retirement import _case
from tests.saas.test_interactive_runner_lease import _admit


async def _retired(c, db_uri, tmp_path, monkeypatch, provider="kubernetes"):
    from kubernetes.client.rest import ApiException

    p = _launcher(tmp_path, monkeypatch, provider)
    binding = _binding(p.delegate, "owned-job", c.authorized.launch["host_id"])
    monkeypatch.setattr(warm, "_reference", lambda **kwargs: replace(binding, **kwargs))
    r = await _case(c, db_uri, monkeypatch, provider=provider)
    assert await r.reaper.sweep_once(now=r.current + 8 * 86400) == 1
    origin = c.journal.read(r.w.root.run_id)
    with r.adapter.bind(c.context):
        host = r.store.get_host(binding.host_id)
    assert host.sandbox_id is host.terminating_sandbox_id is None
    r.driver._app.state.sandbox_config = p.deployment
    conversation = SimpleNamespace(
        host_id=host.host_id, runner_id=origin.official_runner_id, agent_id=None
    )
    r.driver._official.conversation_store = SimpleNamespace(
        get_conversation=lambda _: conversation
    )
    state, reads = SimpleNamespace(exists=None), []

    def read(kind, *args, **kwargs):
        assert current_workspace_id() == c.context.physical_workspace_id
        reads.append((kind, args, kwargs))
        if state.exists == kind:
            return {"metadata": {"uid": str(UUID(int=99))}}
        raise ApiException(status=404, reason="Owned fixture object is absent")

    monkeypatch.setattr(
        p.delegate,
        "_load_batch",
        lambda: SimpleNamespace(
            read_namespaced_job=lambda *args, **kwargs: read("workload", *args, **kwargs)
        ),
    )
    monkeypatch.setattr(
        p.delegate,
        "_load_custom",
        lambda: SimpleNamespace(
            get_namespaced_custom_object=lambda *args, **kwargs: read("workload", *args, **kwargs)
        ),
        raising=False,
    )
    monkeypatch.setattr(
        p.delegate,
        "_load_core",
        lambda: SimpleNamespace(
            read_namespaced_secret=lambda *args, **kwargs: read("secret", *args, **kwargs)
        ),
    )
    second = await r.w.next_lease()
    authorized, _ = await c.executor._authorize(second)
    return SimpleNamespace(**locals())


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
async def test_retired_preflight_requires_actual_absence_and_keeps_the_original_context(
    controller_case, db_uri, tmp_path, monkeypatch, provider
):
    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch, provider)
    outside = current_workspace_id()
    assert outside != c.context.physical_workspace_id
    for kind in ("workload", "secret"):
        g.state.exists = kind
        with pytest.raises(RunnerControlError):
            await g.r.driver.revalidate_managed(g.authorized, (g.origin,), previous=None)
    g.state.exists = None
    admission = await g.r.driver.revalidate_managed(g.authorized, (g.origin,), previous=None)
    assert admission == ManagedGenerationAdmission(g.origin, g.host)
    assert current_workspace_id() == outside
    assert {row[0] for row in g.reads} == {"workload", "secret"}
    assert len(c.inputs) == len(c.gateway_calls) == 1
    with g.r.adapter.bind(c.context):
        assert g.r.store.get_host(g.host.host_id) == g.host


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", [None, "heartbeat", "active", "deleted", "pending"])
async def test_new_generation_uses_a_locked_retired_snapshot_not_an_unconditional_recredential(
    controller_case, db_uri, tmp_path, monkeypatch, drift
):
    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch)
    if drift is not None:
        values = {
            "heartbeat": {"updated_at": g.host.updated_at + 1},
            "active": {"sandbox_id": "another-generation"},
            "deleted": {"deleted_at": now_epoch()},
            "pending": {"terminating_sandbox_id": "another-generation"},
        }[drift]
        with Session(g.r.store._engine) as db:
            db.execute(
                sa.update(SqlHost)
                .where(
                    SqlHost.workspace_id == c.context.physical_workspace_id,
                    SqlHost.host_id == g.host.host_id,
                )
                .values(**values)
            )
            db.commit()
    with g.r.adapter.bind(c.context):
        current = g.r.store.get_host(g.host.host_id, include_deleted=True)
        armed = RetiredGenerationHostStore(g.r.store, g.host).replace_managed_host_sandbox(
            host_id=g.host.host_id,
            user_id=g.host.user_id,
            token="fresh-generation-token",
            provider="kubernetes",
            sandbox_id="fresh-generation",
            token_expires_at=now_epoch() + 3600,
        )
        if drift is None:
            assert armed.sandbox_id == "fresh-generation"
            assert (
                g.r.store.resolve_launch_token(g.host.host_id, "fresh-generation-token")
                is not None
            )
        else:
            assert armed is None
            assert g.r.store.get_host(g.host.host_id, include_deleted=True) == current
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("tracked_launch", [None, "failed", "in_flight", "settled_success"])
async def test_official_preparation_relaunches_the_same_identity_through_the_scoped_store(
    controller_case, db_uri, tmp_path, monkeypatch, tracked_launch
):
    from saas.production import interactive_driver as module

    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch)
    admission = ManagedGenerationAdmission(g.origin, g.host)
    app = FastAPI()
    app.state.managed_launches = ManagedLaunchTracker()
    tracker = app.state.managed_launches
    if tracked_launch is not None:
        tracker.begin(g.authorized.session_id)
        if tracked_launch == "failed":
            tracker.fail(g.authorized.session_id, "isolated previous launch failure")
        elif tracked_launch == "settled_success":
            tracker.get(g.authorized.session_id).settled.set()
    previous_entry = tracker.get(g.authorized.session_id)
    app.state.host_registry = app.state.runner_router = app.state.tunnel_registry = object()
    app.state.sandbox_config = g.p.deployment
    g.r.driver._app = app
    g.r.driver._official.agent_store = object()

    class ProvisionReached(Exception):
        pass

    launch = AsyncMock(side_effect=ProvisionReached)
    monkeypatch.setattr(module.official, "_run_managed_launch", launch)

    async def checkpoint(_):
        pass

    blocked = tracked_launch in {"in_flight", "settled_success"}
    with pytest.raises(RunnerControlError if blocked else ProvisionReached):
        await g.r.driver.prepare(
            g.authorized,
            previous=None,
            generation=admission,
            on_launch=None,
            on_preparation=checkpoint,
            on_resources=checkpoint,
            on_creation=checkpoint,
        )
    if blocked:
        assert launch.await_count == 0
        assert tracker.get(g.authorized.session_id) is previous_entry
        return
    assert launch.await_count == 1
    assert tracker.get(g.authorized.session_id) is not previous_entry
    assert not tracker.get(g.authorized.session_id).settled.is_set()
    assert tracker.get(g.authorized.session_id).error is None
    args = launch.call_args.kwargs
    assert args["relaunch_host"] == g.host
    assert isinstance(args["host_store"], RetiredGenerationHostStore)
    assert args["tracker"] is app.state.managed_launches


@pytest.mark.asyncio
async def test_predecessor_format_binds_complete_history_without_copying_execution_authority(
    controller_case, db_uri, tmp_path, monkeypatch
):
    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch)
    active, _ = await c.executor._prepare_active(g.second, cancellation=asyncio.Event())
    original = active.record
    c.executor._put(
        active,
        managed_predecessor_run_id=g.origin.run_id,
        managed_predecessor_stop_sha256=managed_retirement_proof_sha256(g.origin),
    )
    record = active.record
    assert record.grant == original.grant and record.grant.run_id != g.origin.grant.run_id
    assert (
        record.managed_origin_run_id is record.managed_creation is record.managed_resources is None
    )
    raw = _encode(record)
    assert json.loads(raw)["schema_version"] == 9
    assert _encode(_decode(raw)) == raw and c.journal.read(record.run_id) == record
    for version in range(1, 9):
        value = json.loads(raw)
        value["schema_version"] = version
        with pytest.raises(InteractiveRecoveryError):
            _decode(json.dumps(value).encode())
    for changes in (
        {"managed_predecessor_stop_sha256": "f" * 64},
        {"managed_predecessor_run_id": None, "managed_predecessor_stop_sha256": None},
        {"managed_predecessor_run_id": record.run_id},
    ):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(record, **changes))
    assert c.journal.read(g.origin.run_id) == g.origin


@pytest.mark.asyncio
async def test_predecessor_read_rejects_missing_or_tampered_canonical_history(
    controller_case, db_uri, tmp_path, monkeypatch
):
    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch)
    active, _ = await c.executor._prepare_active(g.second, cancellation=asyncio.Event())
    c.executor._put(
        active,
        managed_predecessor_run_id=g.origin.run_id,
        managed_predecessor_stop_sha256=managed_retirement_proof_sha256(g.origin),
    )
    path = c.journal.root / f"{g.origin.run_id}.json"
    original = path.read_bytes()
    parked = path.with_suffix(".parked")
    try:
        path.rename(parked)
        with pytest.raises(InteractiveRecoveryError):
            c.journal.read(active.record.run_id)
    finally:
        parked.rename(path)
    try:
        for change in ("resource", "project", "runtime_user"):
            value = json.loads(original)
            if change == "resource":
                value["record"]["managed_resources"]["workload_uid"] = str(UUID(int=99))
            elif change == "project":
                value["record"]["scope"]["project_id"] = str(UUID(int=99))
                value["record"]["runtime"]["project_id"] = str(UUID(int=99))
            else:
                value["record"]["runtime"]["runtime_user_key"] = "foreign-runtime-user"
            path.write_text(json.dumps(value))
            with pytest.raises(InteractiveRecoveryError):
                c.journal.read(active.record.run_id)
    finally:
        path.write_bytes(original)
    assert c.journal.read(active.record.run_id) == active.record
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
async def test_pending_old_channel_blocks_rotation_without_rearming_the_host(
    controller_case, db_uri, tmp_path, monkeypatch
):
    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch)
    relay = SimpleNamespace(
        run_id=g.origin.run_id,
        metering_run_id=g.origin.run_id,
        fence_token=g.origin.fence_token,
        capability=g.origin.channel_value,
        app=FastAPI(),
    )
    await c.channels.bind(
        g.origin.scope,
        secret_value=g.origin.channel_value,
        run_id=g.origin.run_id,
        fence_token=g.origin.fence_token,
        relay=relay,
        accepting=False,
    )
    old = c.channels._bound[g.origin.scope.session_id]

    async def preflight(authorized, candidates, *, previous=None):
        return await g.r.driver.revalidate_managed(authorized, candidates, previous=previous)

    c.physical.revalidate_managed = preflight
    preparation = AsyncMock()
    c.physical.prepare = preparation
    try:
        with pytest.raises(RunnerControlError):
            await c.executor.execute(g.second, cancellation=asyncio.Event())
        assert c.channels._bound[g.origin.scope.session_id] is old
        assert c.channels._secrets[g.origin.scope.session_id] == g.origin.channel_value
        assert c.journal.read(g.second.run_id).managed_predecessor_run_id is None
        preparation.assert_not_called()
        with g.r.adapter.bind(c.context):
            assert g.r.store.get_host(g.host.host_id) == g.host
        assert len(c.inputs) == len(c.gateway_calls) == 1
    finally:
        assert await c.channels.suspend(
            g.origin.scope.session_id,
            run_id=g.origin.run_id,
            fence_token=g.origin.fence_token,
            timeout=1,
        )


@pytest.mark.asyncio
async def test_two_fresh_generations_own_their_credentials_resources_and_retirement(
    controller_case, db_uri, tmp_path, monkeypatch
):
    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch)
    origins = [g.origin]
    prepared = []

    async def preflight(authorized, candidates, *, previous=None):
        assert previous is None
        return await g.r.driver.revalidate_managed(authorized, candidates, previous=None)

    async def fresh(
        actual, *, previous, on_launch, on_preparation, on_resources, on_creation, generation
    ):
        assert previous is None and generation.origin == origins[-1]
        row = c.journal.read(actual.run_id)
        assert row.managed_predecessor_run_id == generation.origin.run_id
        index = len(origins)
        token = "fresh-generation-token-" + str(index)
        digest = sha256(token.encode()).hexdigest()
        name = "fresh-generation-" + str(index)
        with g.r.adapter.bind(c.context):
            host = RetiredGenerationHostStore(
                g.r.store, generation.host
            ).replace_managed_host_sandbox(
                host_id=g.host.host_id,
                user_id=g.host.user_id,
                token=token,
                provider="kubernetes",
                sandbox_id=name,
                token_expires_at=now_epoch() + 3600,
            )
        assert host is not None
        await on_preparation(replace(g.binding, resource_name=name))
        intent = ManagedCreationIntent(str(index) * 32, digest)
        for value in (
            intent,
            replace(intent, secret_submitted=True),
            replace(intent, secret_submitted=True, secret_uid=str(UUID(int=10 * index + 2))),
            replace(
                intent,
                secret_submitted=True,
                secret_uid=str(UUID(int=10 * index + 2)),
                workload_submitted=True,
                input_template_sha256="a" * 64,
            ),
        ):
            await on_creation(value)
        await on_resources(
            ManagedResourceBinding(
                str(UUID(int=10 * index + 1)), str(UUID(int=10 * index + 2)), "a" * 64, digest
            )
        )

        async def bind(frame, peer):
            return await on_launch(replace(frame, binding_token=str(index) * 43), peer)

        prepared.append(actual.run_id)
        return await g.r.w.prepare(actual, previous=None, on_launch=bind)

    async def retire(record, checkpoint):
        assert record.run_id == origins[-1].run_id
        return await checkpoint(
            managed_termination=ManagedTerminationReceipt(
                secret_uid=record.managed_creation.secret_uid,
                secret_gone=True,
                pods=(
                    ManagedPodTermination(
                        str(UUID(int=100 + len(origins))), "owned-pod", "d" * 64
                    ),
                ),
                quiescence_sha256="e" * 64,
                complete=True,
            )
        )

    c.physical.revalidate_managed, c.physical.prepare, c.physical.retire_managed = (
        preflight,
        fresh,
        retire,
    )
    monkeypatch.setattr(
        "saas.production.interactive_preparation.inspect_managed_resources",
        lambda deployment, record: record.managed_resources,
    )
    for index in (1, 2):
        if index == 1:
            lease = g.second
        else:
            run_id = _admit(c.f, "c" * 32, text="A third distinct user input")
            claimed = g.r.w.control.claim_run(**g.r.w.machine)
            assert claimed.run_id == run_id
            lease = RunnerControlClientLease(
                **{
                    field.name: getattr(claimed, field.name)
                    for field in fields(RunnerControlClientLease)
                }
            )
            for status in ("starting", "running"):
                g.r.w.control.transition_run(
                    **g.r.w.machine,
                    run_id=lease.run_id,
                    lease_token=lease.lease_token,
                    fence_token=lease.fence_token,
                    capability_token=lease.capability_token,
                    target_status=status,
                )
        try:
            outcome = await c.executor.execute(lease, cancellation=asyncio.Event())
        except Exception as error:
            diagnostics, seen = [], set()
            while error is not None and id(error) not in seen:
                seen.add(id(error))
                diagnostics.append(
                    {
                        "type": type(error).__name__,
                        "frames": [
                            (frame.filename.rsplit("/", 1)[-1], frame.name, frame.lineno)
                            for frame in traceback.extract_tb(error.__traceback__)
                        ],
                    }
                )
                error = error.__cause__ or error.__context__
            pytest.fail(json.dumps(diagnostics))
        assert outcome == "succeeded"
        app = SessionModelChannelMiddleware(FastAPI(), channels=c.channels)
        calls = len(c.gateway_calls)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
            denied = await client.post(
                c.physical.channel.base_url + "/responses",
                headers={"Authorization": "Bearer " + origins[-1].channel_value},
                json={},
            )
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "interactive_model_channel_unavailable"
        assert len(c.gateway_calls) == calls
        await g.r.w.finish(lease)
        record = c.journal.read(lease.run_id)
        assert record.managed_predecessor_run_id == origins[-1].run_id
        assert record.managed_creation != origins[-1].managed_creation
        assert record.official_runner_id != origins[-1].official_runner_id
        assert record.channel_value != origins[-1].channel_value
        assert record.grant.run_id == lease.run_id
        origins.append(record)
        assert await g.r.reaper.sweep_once(now=now_epoch() + 8 * 86400) == 1
        stopped = c.journal.read(record.run_id)
        assert stopped.process_stopped and stopped.managed_termination.complete
        assert c.journal.read(origins[-2].run_id).managed_termination.complete
        origins[-1] = stopped
    assert len(c.inputs) == len(c.gateway_calls) == 3 and len(prepared) == 2
