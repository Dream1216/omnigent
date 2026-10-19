"""SDK write-ahead barriers; scripted effects are not Kubernetes termination proof."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from threading import Event
from types import SimpleNamespace

import pytest

from omnigent.onboarding.sandboxes.kubernetes import KubernetesSandboxLauncher
from saas.production import interactive_preparation as module
from saas.production.interactive_preparation import inspect_managed_resources
from saas.production.interactive_resources import CREATION_ANNOTATION, INPUT_TEMPLATE_ANNOTATION
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_managed_resources import _case


def _stage(intent):
    return (
        "workload"
        if intent.workload_submitted
        else "secret_uid"
        if intent.secret_uid
        else "secret"
        if intent.secret_submitted
        else "reserve"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
async def test_actual_sdk_has_durable_barriers_before_each_create(tmp_path, monkeypatch, provider):
    c = _case(tmp_path, monkeypatch, provider)
    monkeypatch.setattr(
        c.p.delegate, "start_host", KubernetesSandboxLauncher.start_host.__get__(c.p.delegate)
    )
    monkeypatch.setattr(c.p.delegate, "_wait_for_pod_running", lambda *_: None)
    await asyncio.to_thread(
        c.wrap().start_host,
        "owned-job",
        host_id="c" * 32,
        token=c.token,
        host_name="owned-host",
        server_url="https://next.test",
    )
    assert [_stage(row) for row in c.intents] == ["reserve", "secret", "secret_uid", "workload"]
    intent = c.intents[-1]
    assert intent.secret_uid == c.secret["metadata"]["uid"]
    assert c.workload["metadata"]["annotations"][CREATION_ANNOTATION] == intent.nonce
    # The scripted resource read is distinct from the submitted SDK manifest.
    assert intent.workload_submitted and intent.input_template_sha256
    assert c.p.trace.count("sdk-secret") == c.p.trace.count("sdk-create") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["reserve", "secret", "secret_uid", "workload"])
@pytest.mark.parametrize("failure", ["write", "timeout"])
async def test_unacknowledged_intent_cannot_reach_the_next_effect(
    tmp_path, monkeypatch, stage, failure
):
    c = _case(tmp_path, monkeypatch)
    seen = []

    async def checkpoint(intent):
        if _stage(intent) == stage:
            if failure == "write":
                raise OSError("isolated-intent-ack-failed")
            await asyncio.Event().wait()
        seen.append(intent)

    monkeypatch.setattr(module, "_CHECKPOINT_TIMEOUT_SECONDS", 0.03)
    with pytest.raises((RunnerControlError, OSError)):
        await asyncio.to_thread(
            c.wrap(creation_callback=checkpoint).start_host,
            "owned-job",
            host_id="c" * 32,
            token=c.token,
        )
    assert c.p.trace.count("sdk-secret") == (1 if stage in {"secret_uid", "workload"} else 0)
    assert "sdk-create" not in c.p.trace and "startup-continued" not in c.p.trace
    assert stage not in [_stage(intent) for intent in seen]
    assert not c.resources


@pytest.mark.asyncio
async def test_unknown_secret_ack_retains_submission_without_starting_workload(
    tmp_path, monkeypatch
):
    c = _case(tmp_path, monkeypatch)
    original = c.create_secret

    def rejected(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("isolated-secret-create-ack-rejected")

    core = c.p.delegate._load_core()
    core.create_namespaced_secret = rejected
    monkeypatch.setattr(c.p.delegate, "_load_core", lambda: core)
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert [_stage(row) for row in c.intents] == ["reserve", "secret"]
    assert c.intents[-1].secret_uid is None and not c.intents[-1].workload_submitted
    assert c.p.trace.count("sdk-secret") == 1 and "sdk-create" not in c.p.trace
    assert c.secret["metadata"]["annotations"][CREATION_ANNOTATION] == c.intents[-1].nonce
    assert not c.resources


@pytest.mark.asyncio
async def test_stop_while_secret_create_is_in_flight_prevents_workload_submit(
    tmp_path, monkeypatch
):
    c = _case(tmp_path, monkeypatch)
    entered, release = Event(), Event()
    core = c.p.delegate._load_core()

    def paused(*args, **kwargs):
        c.create_secret(*args, **kwargs)
        entered.set()
        assert release.wait(5)

    core.create_namespaced_secret = paused
    monkeypatch.setattr(c.p.delegate, "_load_core", lambda: core)
    task = asyncio.create_task(
        asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    )
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        c.p.stopping.set()
    finally:
        release.set()
    with pytest.raises(RunnerControlError):
        await task
    assert [_stage(row) for row in c.intents] == ["reserve", "secret", "secret_uid"]
    assert "sdk-create" not in c.p.trace and not c.resources


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift", ["secret_nonce", "workload_nonce", "template_nonce", "template_digest", "secret_uid"]
)
async def test_observed_resources_require_the_same_creation_identity(tmp_path, monkeypatch, drift):
    c = _case(tmp_path, monkeypatch)
    await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    record = SimpleNamespace(
        managed_preparation=c.p.recorded[0],
        managed_resources=c.resources[0],
        managed_creation=c.intents[-1],
    )
    if drift == "secret_nonce":
        c.secret["metadata"]["annotations"][CREATION_ANNOTATION] = "f" * 32
    elif drift == "workload_nonce":
        c.workload["metadata"]["annotations"][CREATION_ANNOTATION] = "f" * 32
    elif drift == "template_nonce":
        c.template["metadata"]["annotations"][CREATION_ANNOTATION] = "f" * 32
    elif drift == "template_digest":
        c.template["metadata"]["annotations"][INPUT_TEMPLATE_ANNOTATION] = "f" * 64
    else:
        record.managed_creation = replace(
            c.intents[-1], secret_uid="00000000-0000-0000-0000-000000000009"
        )
    with pytest.raises(RunnerControlError):
        inspect_managed_resources(c.p.deployment, record)
