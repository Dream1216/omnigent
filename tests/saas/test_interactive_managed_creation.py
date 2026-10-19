"""Managed SDK effect contracts; scripted API calls are not physical termination proof."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from threading import Event
from types import SimpleNamespace

import pytest

from omnigent.onboarding.sandboxes.agent_sandbox import AgentSandboxLauncher
from omnigent.onboarding.sandboxes.kubernetes import KubernetesSandboxLauncher
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_preparation import _reference
from tests.saas.test_interactive_managed_resources import _case


@pytest.mark.asyncio
async def test_one_reserved_creation_cannot_submit_the_workload_twice(tmp_path, monkeypatch):
    c = _case(tmp_path, monkeypatch)

    def twice(*args, **kwargs):
        c.p.delegate._create_workload("owned-runners", c.job)
        c.p.delegate._create_workload("owned-runners", c.job)

    monkeypatch.setattr(c.p.delegate, "start_host", twice)
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert c.p.trace.count("sdk-create") == 1


@pytest.mark.asyncio
async def test_checkpointed_sdk_does_not_run_name_only_best_effort_cleanup(tmp_path, monkeypatch):
    c = _case(tmp_path, monkeypatch)
    deleted = []
    monkeypatch.setattr(c.p.delegate, "_best_effort_delete", lambda *args: deleted.append(args))

    def failed(*args, **kwargs):
        c.p.delegate._create_workload("owned-runners", c.job)
        c.p.delegate._best_effort_delete("owned-runners", "owned-job", "owned-token")
        raise OSError("isolated-create-ack-unavailable")

    monkeypatch.setattr(c.p.delegate, "start_host", failed)
    with pytest.raises((OSError, RunnerControlError)):
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert not deleted


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["terminate", "resume"])
async def test_unbound_lifecycle_mutation_is_unavailable(tmp_path, monkeypatch, action):
    c = _case(tmp_path, monkeypatch)
    effects = []
    monkeypatch.setattr(c.p.delegate, action, lambda *args: effects.append(args))
    with pytest.raises(RunnerControlError):
        getattr(c.wrap(), action)("owned-job")
    assert not effects


@pytest.mark.asyncio
async def test_unknown_create_ack_retains_real_reads_but_never_continues_startup(
    tmp_path, monkeypatch
):
    c = _case(tmp_path, monkeypatch)

    def committed_but_rejected(*_args):
        c.p.trace.append("sdk-create")
        raise OSError("isolated-rejected-ack-body-must-stay-private")

    monkeypatch.setattr(c.p.delegate, "_create_workload", committed_but_rejected)
    with pytest.raises(RunnerControlError) as failed:
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert "body-must-stay-private" not in str(failed.value)
    assert len(c.resources) == 1 and c.p.trace.count("sdk-create") == 1
    assert c.resources[0].workload_uid == c.workload["metadata"]["uid"]
    assert "startup-continued" not in c.p.trace


@pytest.mark.asyncio
async def test_agent_sandbox_create_conflict_cannot_wake_an_existing_object(tmp_path, monkeypatch):
    ApiException = pytest.importorskip("kubernetes.client.rest").ApiException

    c = _case(tmp_path, monkeypatch, "agent_sandbox")
    created, changed = [], []

    def conflict(*args, **kwargs):
        created.append(args)
        raise ApiException(status=409, reason="isolated-name-conflict")

    client = SimpleNamespace(
        create_namespaced_custom_object=conflict,
        patch_namespaced_custom_object=lambda *args, **kwargs: changed.append(args),
    )
    monkeypatch.setattr(c.p.delegate, "_load_custom", lambda: client)
    monkeypatch.setattr(
        c.p.delegate,
        "_create_workload",
        AgentSandboxLauncher._create_workload.__get__(c.p.delegate),
    )
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert len(created) == 1 and not changed and not c.resources


@pytest.mark.asyncio
async def test_consumed_launcher_does_not_close_clients_on_a_second_start(tmp_path, monkeypatch):
    c = _case(tmp_path, monkeypatch)
    wrapped = c.wrap()
    await asyncio.to_thread(wrapped.start_host, "owned-job", host_id="c" * 32, token=c.token)
    before = c.p.trace.copy()
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(wrapped.start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert c.p.trace == before


@pytest.mark.asyncio
async def test_controller_rejects_a_second_managed_preparation_checkpoint(
    controller_case, monkeypatch
):
    c = controller_case
    authorize = c.executor._authorize

    async def managed(lease):
        actual, issued = await authorize(lease)
        return replace(
            actual,
            launch={**actual.launch, "host_type": "managed", "sandbox_provider": "kubernetes"},
        ), issued

    async def prepare(_actual, **values):
        await values["on_preparation"](_reference())
        with pytest.raises(RunnerControlError):
            await values["on_preparation"](_reference())
        raise RunnerControlError("isolated_preparation_ended", "Unavailable")

    monkeypatch.setattr(c.executor, "_authorize", managed)
    monkeypatch.setattr(c.physical, "prepare", prepare)
    with pytest.raises(RunnerControlError):
        await c.executor.execute(c.lease, cancellation=asyncio.Event())
    record = c.journal.read(c.lease.run_id)
    assert record.managed_preparation == _reference() and not record.process_stopped


@pytest.mark.asyncio
async def test_concurrent_start_cannot_close_the_live_sdk_client(tmp_path, monkeypatch):
    c = _case(tmp_path, monkeypatch)
    entered, released = Event(), Event()

    def create(*_args):
        c.p.trace.append("sdk-create")
        entered.set()
        assert released.wait(5)

    monkeypatch.setattr(c.p.delegate, "_create_workload", create)
    wrapped = c.wrap()
    running = asyncio.create_task(
        asyncio.to_thread(wrapped.start_host, "owned-job", host_id="c" * 32, token=c.token)
    )
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        with pytest.raises(RunnerControlError):
            await asyncio.to_thread(
                wrapped.start_host, "owned-job", host_id="c" * 32, token=c.token
            )
        assert "close-client" not in c.p.trace
    finally:
        released.set()
        await running
    assert c.p.trace.count("sdk-create") == c.p.trace.count("close-client") == 1


@pytest.mark.asyncio
async def test_actual_sdk_secret_conflict_does_not_delete_existing_resources(
    tmp_path, monkeypatch
):
    import click

    ApiException = pytest.importorskip("kubernetes.client.rest").ApiException

    c = _case(tmp_path, monkeypatch)
    created, deleted = [], []

    def secret_conflict(*args, **kwargs):
        created.append(args)
        raise ApiException(status=409, reason="isolated-foreign-secret")

    core = SimpleNamespace(
        create_namespaced_secret=secret_conflict,
        delete_namespaced_secret=lambda *args, **kwargs: deleted.append(("secret", args)),
        delete_namespaced_pod=lambda *args, **kwargs: deleted.append(("pod", args)),
    )
    batch = SimpleNamespace(
        delete_namespaced_job=lambda *args, **kwargs: deleted.append(("job", args))
    )
    monkeypatch.setattr(c.p.delegate, "_load_core", lambda: core)
    monkeypatch.setattr(c.p.delegate, "_load_batch", lambda: batch)
    monkeypatch.setattr(
        c.p.delegate, "start_host", KubernetesSandboxLauncher.start_host.__get__(c.p.delegate)
    )
    with pytest.raises(click.ClickException):
        await asyncio.to_thread(
            c.wrap().start_host,
            "owned-job",
            host_id="c" * 32,
            token=c.token,
            host_name="owned-host",
            server_url="https://next.test",
        )
    assert len(created) == 1 and not deleted and not c.resources
