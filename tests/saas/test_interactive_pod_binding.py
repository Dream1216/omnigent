"""Constructed SDK/Journal observations; actual kubelet expiry and resume are separate."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID

import pytest

from omnigent.onboarding.sandboxes.agent_sandbox import API_GROUP, API_VERSION
from saas.production.interactive_pod_binding import read_running_pod
from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    InteractiveRecoveryJournal,
    ManagedCreationIntent,
    ManagedPodTermination,
    ManagedResourceBinding,
    ManagedTerminationReceipt,
    _decode,
    _encode,
    managed_retirement_proof_sha256,
    physical_recovery_proof_sha256,
)
from saas.production.interactive_resources import TERMINATION_FINALIZER
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_preparation import _reference
from tests.saas.test_interactive_managed_resources import _case, _resources


def _pod_case(tmp_path, monkeypatch):
    c = _case(tmp_path, monkeypatch, "agent_sandbox")
    uid, effects = str(UUID(int=3)), []
    state = SimpleNamespace(pod=None, drift=None, fail_checkpoint=False, checkpoint_count=0)
    core = c.p.delegate._load_core()

    def read_pod(name, namespace, **kwargs):
        assert (name, namespace) == ("owned-job", "owned-runners")
        assert kwargs == {"_request_timeout": 10}
        if state.pod is None:
            state.pod = copy.deepcopy(c.template)
            state.pod["metadata"].update(
                uid=uid,
                name=name,
                namespace=namespace,
                resourceVersion="opaque-pod-rv",
                finalizers=["other.test/keep"],
                ownerReferences=[
                    {
                        "apiVersion": API_GROUP + "/" + API_VERSION,
                        "kind": "Sandbox",
                        "name": "owned-job",
                        "uid": c.workload["metadata"]["uid"],
                        "controller": True,
                        "blockOwnerDeletion": True,
                    }
                ],
            )
            state.pod["status"] = {"phase": "Running"}
            if state.drift == "nonce":
                state.pod["metadata"]["annotations"]["saas.omnigent.ai/creation-nonce"] = "f" * 32
            elif state.drift == "owner":
                state.pod["metadata"]["ownerReferences"][0]["uid"] = str(UUID(int=99))
            elif state.drift == "deleted":
                state.pod["metadata"]["deletionTimestamp"] = "2026-10-20T00:00:00Z"
            elif state.drift == "pending":
                state.pod["status"]["phase"] = "Pending"
            elif state.drift == "invalid_uid":
                state.pod["metadata"]["uid"] = "fabricated"
        return copy.deepcopy(state.pod)

    def patch(path, method, **kwargs):
        assert c.intents[-1].pod_uid == uid
        assert c.intents[-1].pod_name == "owned-job"
        assert path == "/api/v1/namespaces/owned-runners/pods/owned-job" and method == "PATCH"
        assert kwargs["header_params"]["Content-Type"] == "application/json-patch+json"
        assert kwargs["body"] == [
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "opaque-pod-rv"},
            {
                "op": "add",
                "path": "/metadata/finalizers",
                "value": ["other.test/keep", TERMINATION_FINALIZER],
            },
        ]
        if state.drift == "patch":
            raise OSError("isolated-private-sdk-body-not-for-the-user")
        effects.append(copy.deepcopy(kwargs["body"]))
        if state.drift != "lost_effect":
            state.pod["metadata"].update(
                finalizers=["other.test/keep", TERMINATION_FINALIZER],
                resourceVersion="opaque-pod-rv-2",
            )
        if state.drift == "replacement_after_patch":
            state.pod["metadata"]["uid"] = str(UUID(int=99))
        return copy.deepcopy(state.pod)

    core.read_namespaced_pod = read_pod
    monkeypatch.setattr(c.p.delegate, "_load_core", lambda: core)
    c.p.delegate._api_client.call_api = patch
    monkeypatch.setattr(c.p.delegate, "_wait_for_pod_running", lambda *_: None)

    def start(*args, **kwargs):
        workspace = c.start(*args, **kwargs)
        c.p.delegate._wait_for_pod_running("owned-runners", "owned-job")
        return workspace

    monkeypatch.setattr(c.p.delegate, "start_host", start)

    async def creation(intent):
        if intent.pod_uid is not None:
            if state.fail_checkpoint:
                raise OSError("isolated-private-checkpoint-rejected")
            state.checkpoint_count += 1
            if state.drift == "stop_after_checkpoint":
                c.p.stopping.set()
        await c.checkpoint_creation(intent)

    async def run():
        return await asyncio.to_thread(
            c.wrap(creation_callback=creation).start_host,
            "owned-job",
            host_id="c" * 32,
            token=c.token,
        )

    return SimpleNamespace(**locals())


@pytest.mark.asyncio
async def test_agent_pod_is_bound_before_uid_conditional_protection(tmp_path, monkeypatch):
    p = _pod_case(tmp_path, monkeypatch)
    assert await p.run() == "/workspace"
    assert p.state.checkpoint_count == len(p.effects) == 1
    assert p.c.intents[-1].pod_uid == p.uid and p.c.intents[-1].pod_name == "owned-job"
    assert p.state.pod["metadata"]["finalizers"] == ["other.test/keep", TERMINATION_FINALIZER]
    assert p.c.intents[-1].workload_submitted and len(p.c.resources) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift",
    [
        "nonce",
        "owner",
        "deleted",
        "pending",
        "invalid_uid",
        "patch",
        "lost_effect",
        "replacement_after_patch",
        "stop_after_checkpoint",
        "checkpoint",
    ],
)
async def test_invalid_or_unacknowledged_pod_never_allows_successful_start(
    tmp_path, monkeypatch, drift
):
    p = _pod_case(tmp_path, monkeypatch)
    p.state.drift = drift
    p.state.fail_checkpoint = drift == "checkpoint"
    with pytest.raises(RunnerControlError) as raised:
        await p.run()
    assert str(raised.value) == "Interactive execution is unavailable"
    if drift not in {"lost_effect", "replacement_after_patch"}:
        assert not p.effects
    assert p.c.p.trace[-1] == "close-client"


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["replacement", "deleted", "marker_removed"])
async def test_warm_pod_reads_reject_replacement_or_termination(tmp_path, monkeypatch, drift):
    p = _pod_case(tmp_path, monkeypatch)
    await p.run()
    if drift == "replacement":
        p.state.pod["metadata"]["uid"] = str(UUID(int=99))
    elif drift == "deleted":
        p.state.pod["metadata"]["deletionTimestamp"] = "2026-10-20T00:00:00Z"
    else:
        p.state.pod["metadata"]["finalizers"].remove(TERMINATION_FINALIZER)
    with pytest.raises(RunnerControlError):
        read_running_pod(p.c.p.delegate, p.c.p.recorded[0], p.c.intents[-1], p.c.resources[0])


@pytest.mark.asyncio
async def test_pod_identity_private_v10_is_immutable_and_not_a_stop_fact(controller_case):
    c = controller_case
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    c.executor._put(active, managed_preparation=_reference(provider="agent_sandbox"))
    intent = ManagedCreationIntent("a" * 32, "b" * 64)
    for value in (
        intent,
        replace(intent, secret_submitted=True),
        replace(intent, secret_submitted=True, secret_uid=str(UUID(int=2))),
        replace(
            intent,
            secret_submitted=True,
            secret_uid=str(UUID(int=2)),
            workload_submitted=True,
            input_template_sha256="a" * 64,
        ),
    ):
        c.executor._put(active, managed_creation=value)
    c.executor._put(active, managed_resources=_resources())
    before = active.record
    assert json.loads(_encode(before))["schema_version"] == 5
    creation = replace(before.managed_creation, pod_uid=str(UUID(int=3)), pod_name="owned-job")
    c.executor._put(active, managed_creation=creation)
    record, raw = active.record, _encode(active.record)
    assert json.loads(raw)["schema_version"] == 10
    assert _encode(_decode(raw)) == raw and c.journal.read(record.run_id) == record
    with pytest.raises(InteractiveRecoveryError):
        physical_recovery_proof_sha256(record)
    with pytest.raises(InteractiveRecoveryError):
        replace(
            record,
            managed_termination=ManagedTerminationReceipt(
                pods=(ManagedPodTermination(str(UUID(int=99)), "other-pod"),),
                secret_uid=creation.secret_uid,
            ),
        )
    for intent in (
        before.managed_creation,
        replace(creation, pod_uid=str(UUID(int=99))),
        replace(creation, pod_name="other-pod"),
    ):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(record, managed_creation=intent))
    for version in range(1, 10):
        document = json.loads(raw)
        document["schema_version"] = version
        with pytest.raises(InteractiveRecoveryError):
            _decode(json.dumps(document).encode())
    c.executor._active.pop(c.lease.run_id).meter.close(timeout_seconds=0)
    c.journal.close()
    reopened = InteractiveRecoveryJournal(c.journal.root)
    try:
        assert reopened.read(record.run_id) == record
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_v10_preserves_the_v9_predecessor_without_reusing_its_authority(
    controller_case, db_uri, tmp_path, monkeypatch
):
    from tests.saas.test_interactive_managed_generation import _retired

    c = controller_case
    g = await _retired(c, db_uri, tmp_path, monkeypatch, "agent_sandbox")
    active, _ = await c.executor._prepare_active(g.second, cancellation=asyncio.Event())
    c.executor._put(
        active,
        managed_predecessor_run_id=g.origin.run_id,
        managed_predecessor_stop_sha256=managed_retirement_proof_sha256(g.origin),
    )
    c.executor._put(active, phase="preparing")
    c.executor._put(active, managed_preparation=replace(g.binding, resource_name="fresh-sandbox"))
    base = ManagedCreationIntent("b" * 32, "d" * 64)
    for intent in (
        base,
        replace(base, secret_submitted=True),
        replace(base, secret_submitted=True, secret_uid=str(UUID(int=5))),
        replace(
            base,
            secret_submitted=True,
            secret_uid=str(UUID(int=5)),
            workload_submitted=True,
            input_template_sha256="a" * 64,
        ),
    ):
        c.executor._put(active, managed_creation=intent)
    c.executor._put(
        active,
        managed_resources=ManagedResourceBinding(
            str(UUID(int=4)), str(UUID(int=5)), "a" * 64, "d" * 64
        ),
    )
    c.executor._put(
        active,
        managed_creation=replace(
            active.record.managed_creation, pod_uid=str(UUID(int=6)), pod_name="fresh-sandbox"
        ),
    )
    row = active.record
    assert json.loads(_encode(row))["schema_version"] == 10
    assert _decode(_encode(row)) == c.journal.read(row.run_id) == row
    assert row.managed_predecessor_run_id == g.origin.run_id
    assert row.grant.run_id == g.second.run_id != g.origin.grant.run_id
    assert c.journal.read(g.origin.run_id) == g.origin
