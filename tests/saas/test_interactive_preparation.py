"""Actual thread cancellation contracts, not real Sandbox or provider cleanup proof."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from omnigent.host.frames import HostLaunchRunnerFrame, encode_host_frame
from omnigent.server.managed_hosts import (
    ManagedLaunchTracker,
    ManagedSandboxConfig,
    ManagedSandboxDeployment,
)
from saas.production import interactive_driver as module
from saas.production.interactive_driver import OfficialInteractiveDriver
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http


def _preparing(c, monkeypatch):
    entered, resume, finished = threading.Event(), threading.Event(), threading.Event()
    allocated, forwarded, wired = [], [], []
    authorized = replace(
        c.authorized,
        launch={**c.authorized.launch, "host_type": "managed", "sandbox_provider": "kubernetes"},
    )
    app = FastAPI()
    app.state.host_registry = SimpleNamespace(
        send_text=lambda *_: forwarded.append(True),
    )
    app.state.runner_router = object()
    app.state.tunnel_registry = object()
    app.state.sandbox_config = ManagedSandboxDeployment.single(
        ManagedSandboxConfig(
            server_url="https://next.test",
            launcher_factory=lambda: None,
            token_ttl_s=3600,
            provider="kubernetes",
        )
    )
    app.state.managed_launches = ManagedLaunchTracker()
    conversation = SimpleNamespace(host_id=None, agent_id=None)
    dependencies = SimpleNamespace(
        conversation_store=SimpleNamespace(get_conversation=lambda _: conversation),
        host_store=object(),
        agent_store=object(),
    )
    driver = OfficialInteractiveDriver(
        app=app, dependencies=dependencies, contract_version="0.2.0"
    )

    def provision():
        entered.set()
        try:
            assert resume.wait(5), "owned preparation thread was not released"
            allocated.append(True)
        finally:
            finished.set()

    async def launch(**_):
        await asyncio.to_thread(provision)
        conversation.host_id = "prepared-host"

    async def connect(**values):
        peer = SimpleNamespace(
            hello=SimpleNamespace(capabilities={"saas.model-channel.v1"}),
            pending_launches={},
            owner=authorized.runtime.runtime_user_key,
            account_generation=None,
        )
        frame = HostLaunchRunnerFrame(
            "prepare-request", "x" * 43, "/workspace", authorized.session_id, "openai-agents"
        )
        values["app_state"].host_registry.send_text(peer, encode_host_frame(frame))
        return None, conversation

    async def wire(frame, _peer):
        wired.append(True)
        return frame

    async def checkpoint(_binding):
        pass

    # This fixture proves worker lifetime, not resource identity or creation.
    monkeypatch.setattr(module, "bind_managed_preparation", lambda deployment, **_: deployment)
    monkeypatch.setattr(module.official, "_run_managed_launch", launch)
    monkeypatch.setattr(module.official, "ensure_runner_connected", connect)
    return SimpleNamespace(**locals())


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupt_quiescence", (False, True, "deadline"))
async def test_cancelled_prepare_keeps_actual_worker_and_denies_late_runner_launch(
    controller_case, monkeypatch, interrupt_quiescence
):
    p = _preparing(controller_case, monkeypatch)
    execution = asyncio.create_task(
        p.driver.prepare(
            p.authorized,
            previous=None,
            on_launch=p.wire,
            on_preparation=p.checkpoint,
            on_resources=p.checkpoint,
        )
    )
    quiescence = None
    try:
        assert await asyncio.to_thread(p.entered.wait, 2)
        execution.cancel()
        with pytest.raises(asyncio.CancelledError):
            await execution
        if interrupt_quiescence == "deadline":
            monkeypatch.setattr(module, "_PREPARATION_QUIESCE_TIMEOUT_S", 0.03)
        quiescence = asyncio.create_task(p.driver.quiesce_preparation(p.authorized))
        if interrupt_quiescence == "deadline":
            with pytest.raises(RunnerControlError):
                await asyncio.wait_for(quiescence, 1)
            monkeypatch.setattr(module, "_PREPARATION_QUIESCE_TIMEOUT_S", 10)
            quiescence = asyncio.create_task(p.driver.quiesce_preparation(p.authorized))
        else:
            await asyncio.sleep(0.02)
            assert not quiescence.done(), "task cancellation is not worker quiescence"
            if interrupt_quiescence:
                quiescence.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await quiescence
                quiescence = asyncio.create_task(p.driver.quiesce_preparation(p.authorized))
        with pytest.raises(RunnerControlError):
            await asyncio.wait_for(
                p.driver.prepare(p.authorized, previous=None, on_launch=p.wire), 0.1
            )
    finally:
        p.resume.set()
        assert await asyncio.to_thread(p.finished.wait, 2)
        if quiescence is not None:
            await asyncio.wait_for(quiescence, 2)
        if not execution.done():
            await asyncio.gather(execution, return_exceptions=True)
    assert p.allocated == [True] and not p.wired and not p.forwarded


@pytest.mark.asyncio
async def test_cancelled_preparation_releases_a_late_handle_without_leaking_its_listener(
    controller_case, monkeypatch
):
    p = _preparing(controller_case, monkeypatch)
    entered, resume, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def listen():
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    listener = asyncio.create_task(listen())
    handle = SimpleNamespace(authorized=p.authorized, listener=listener)

    async def prepare(*_, **__):
        entered.set()
        await resume.wait()
        p.driver._handles[p.driver._key(p.authorized)] = handle
        return handle

    monkeypatch.setattr(p.driver, "_prepare", prepare)
    execution = asyncio.create_task(
        p.driver.prepare(p.authorized, previous=None, on_launch=p.wire)
    )
    try:
        await asyncio.wait_for(entered.wait(), 2)
        execution.cancel()
        with pytest.raises(asyncio.CancelledError):
            await execution
        with pytest.raises(RunnerControlError):
            await p.driver.release(handle)
        resume.set()
        await asyncio.wait_for(
            asyncio.gather(
                p.driver.quiesce_preparation(p.authorized),
                p.driver.quiesce_preparation(p.authorized),
            ),
            2,
        )
        assert closed.is_set() and listener.done()
        assert not p.driver._handles and not p.driver._preparations
    finally:
        resume.set()
        listener.cancel()
        await asyncio.gather(listener, return_exceptions=True)
        await asyncio.gather(execution, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", (False, True))
async def test_preparation_result_and_failure_are_observed_without_retaining_a_finished_slot(
    controller_case, monkeypatch, fail
):
    p = _preparing(controller_case, monkeypatch)
    handle = object()

    async def prepare(*_, **__):
        if fail:
            raise RuntimeError("isolated-preparation-error")
        return handle

    monkeypatch.setattr(p.driver, "_prepare", prepare)
    if fail:
        with pytest.raises(RuntimeError, match="isolated-preparation-error"):
            await p.driver.prepare(p.authorized, previous=None, on_launch=p.wire)
    else:
        assert await p.driver.prepare(p.authorized, previous=None, on_launch=p.wire) is handle
    assert not p.driver._preparations
