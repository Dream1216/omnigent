"""Scripted SDK metadata contracts; UUID fixtures are not real deletion or Pod-recovery proof."""

from __future__ import annotations

import asyncio
import base64
import copy
import json
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace
from uuid import UUID

import pytest

from omnigent.host.identity import HOST_ID_ENV_VAR, HOST_TOKEN_ENV_VAR
from omnigent.onboarding.sandboxes.agent_sandbox import build_sandbox_manifest
from omnigent.onboarding.sandboxes.agent_sandbox_warm_pool import AgentSandboxWarmPoolLauncher
from omnigent.onboarding.sandboxes.kubernetes import (
    _token_secret_name,
    build_job_manifest,
    build_token_secret_manifest,
)
from saas.production import interactive_preparation as module
from saas.production.interactive_preparation import (
    bind_managed_preparation,
    inspect_managed_resources,
)
from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    InteractiveRecoveryJournal,
    ManagedResourceBinding,
    physical_recovery_proof_sha256,
)
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_preparation import _launcher, _reference


def _resources(**changes):
    return replace(
        ManagedResourceBinding(str(UUID(int=1)), str(UUID(int=2)), "a" * 64, "b" * 64),
        **changes,
    )


def _case(tmp_path, monkeypatch, provider="kubernetes"):
    p = _launcher(
        tmp_path,
        monkeypatch,
        provider,
        **({"launcher_type": AgentSandboxWarmPoolLauncher} if provider == "agent_sandbox" else {}),
    )
    secret_name = _token_secret_name("owned-job")
    token = p.token
    assert not hasattr(p.host, "token_hash")
    job = build_job_manifest(
        job_name="owned-job",
        namespace="owned-runners",
        image=p.delegate._resolve_image(),
        service_account="powerless",
        host_id="c" * 32,
        host_name="owned-host",
        server_url="https://next.test",
        token_secret_name=secret_name,
        harness_secret=None,
        env_literals={},
        node_selector=None,
        workspace="/home/omnigent/workspace",
    )
    workload = (
        job
        if provider == "kubernetes"
        else build_sandbox_manifest(
            job, shutdown_time="2026-10-19T00:00:00Z", workspace_volume=None
        )
    )
    workload["metadata"]["uid"] = str(UUID(int=1))
    secret = build_token_secret_manifest(
        secret_name=secret_name, namespace="owned-runners", token=token
    )
    secret.pop("stringData")
    secret["metadata"]["uid"] = str(UUID(int=2))
    secret["data"] = {HOST_TOKEN_ENV_VAR: base64.b64encode(token.encode()).decode()}
    template = workload["spec"]["template" if provider == "kubernetes" else "podTemplate"]
    p.delegate._api_client.sanitize_for_serialization = copy.deepcopy
    reads, resources = [], []

    def read_workload(*args, **kwargs):
        reads.append(("workload", args, kwargs))
        p.trace.append("read-workload")
        return copy.deepcopy(workload)

    def read_secret(*args, **kwargs):
        reads.append(("secret", args, kwargs))
        p.trace.append("read-secret")
        return copy.deepcopy(secret)

    monkeypatch.setattr(
        p.delegate, "_load_batch", lambda: SimpleNamespace(read_namespaced_job=read_workload)
    )
    monkeypatch.setattr(
        p.delegate,
        "_load_custom",
        lambda: SimpleNamespace(get_namespaced_custom_object=read_workload),
        raising=False,
    )
    monkeypatch.setattr(
        p.delegate, "_load_core", lambda: SimpleNamespace(read_namespaced_secret=read_secret)
    )
    monkeypatch.setattr(p.delegate, "_create_workload", lambda *_: p.trace.append("sdk-create"))

    def start(*_, **__):
        p.delegate._create_workload("owned-runners", job)
        p.trace.append("startup-continued")
        return "/workspace"

    monkeypatch.setattr(p.delegate, "start_host", start)

    async def checkpoint_resources(binding):
        resources.append(binding)
        p.trace.append("resources")

    def wrap(callback=checkpoint_resources):
        return bind_managed_preparation(
            p.deployment,
            provider=provider,
            host_store=p.host_store,
            owner="owned-user",
            checkpoint=p.checkpoint,
            checkpoint_resources=callback,
            stopping=p.stopping,
            loop=asyncio.get_running_loop(),
        ).default.launcher_factory()

    return SimpleNamespace(**locals())


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ("kubernetes", "agent_sandbox"))
async def test_created_uid_checkpoint_precedes_sdk_continuation(tmp_path, monkeypatch, provider):
    c = _case(tmp_path, monkeypatch, provider)
    assert (
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
        == "/workspace"
    )
    assert c.p.trace == [
        "load-config",
        "checkpoint",
        "sdk-create",
        "load-config",
        "read-workload",
        "read-secret",
        "resources",
        "startup-continued",
        "close-client",
    ]
    assert len(c.resources) == 1
    result = c.resources[0]
    assert result.workload_uid == c.workload["metadata"]["uid"]
    assert result.token_secret_uid == c.secret["metadata"]["uid"]
    assert result.host_token_sha256 == sha256(c.token.encode()).hexdigest()
    assert c.token not in repr(result)
    assert all(read[2] == {"_request_timeout": 10} for read in c.reads)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift",
    (
        "namespace",
        "kind",
        "api_version",
        "labels",
        "host_id",
        "image",
        "env_from",
        "mount_token",
        "duplicate_env",
        "reference",
        "optional_reference",
        "deleted",
        "bad_uid",
        "secret_kind",
        "secret_namespace",
        "secret_token",
        "secret_encoding",
    ),
)
async def test_mismatched_created_objects_never_continue_startup(tmp_path, monkeypatch, drift):
    c = _case(tmp_path, monkeypatch)
    host = c.template["spec"]["containers"][0]
    env = {item["name"]: item for item in host["env"]}
    if drift == "namespace":
        c.workload["metadata"]["namespace"] = "foreign"
    elif drift == "kind":
        c.workload["kind"] = "Deployment"
    elif drift == "api_version":
        c.workload["apiVersion"] = "foreign/v1"
    elif drift == "labels":
        c.workload["metadata"]["labels"] = {}
    elif drift == "host_id":
        env[HOST_ID_ENV_VAR]["value"] = "d" * 32
    elif drift == "image":
        host["image"] += "-foreign"
    elif drift == "env_from":
        host["envFrom"] = [{"secretRef": {"name": "foreign"}}]
    elif drift == "mount_token":
        c.template["spec"]["automountServiceAccountToken"] = True
    elif drift == "duplicate_env":
        host["env"].append(copy.deepcopy(host["env"][0]))
    elif drift in {"reference", "optional_reference"}:
        ref = env[HOST_TOKEN_ENV_VAR]["valueFrom"]["secretKeyRef"]
        ref["name" if drift == "reference" else "optional"] = (
            "foreign" if drift == "reference" else True
        )
    elif drift == "deleted":
        c.workload["metadata"]["deletionTimestamp"] = "2026-10-19T00:00:00Z"
    elif drift == "bad_uid":
        c.workload["metadata"]["uid"] = "fabricated"
    elif drift == "secret_kind":
        c.secret["kind"] = "ConfigMap"
    elif drift == "secret_namespace":
        c.secret["metadata"]["namespace"] = "foreign"
    elif drift == "secret_token":
        c.secret["data"][HOST_TOKEN_ENV_VAR] = base64.b64encode(b"foreign").decode()
    else:
        c.secret["data"][HOST_TOKEN_ENV_VAR] = "invalid base64"
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert not c.resources and "startup-continued" not in c.p.trace


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("write", "timeout", "missing"))
async def test_unacknowledged_resource_fact_never_continues_or_claims_cleanup(
    tmp_path, monkeypatch, failure
):
    c = _case(tmp_path, monkeypatch)

    async def reject(_binding):
        if failure == "write":
            raise OSError("isolated-private-volume-write")
        await asyncio.Event().wait()

    if failure == "missing":

        def missing(*_, **__):
            raise OSError("isolated-object-missing; body-must-stay-private")

        monkeypatch.setattr(
            c.p.delegate, "_load_batch", lambda: SimpleNamespace(read_namespaced_job=missing)
        )
    monkeypatch.setattr(module, "_CHECKPOINT_TIMEOUT_SECONDS", 0.03)
    with pytest.raises((RunnerControlError, OSError)) as failure_result:
        await asyncio.to_thread(
            c.wrap(reject).start_host, "owned-job", host_id="c" * 32, token=c.token
        )
    assert "body-must-stay-private" not in str(failure_result.value)
    assert c.p.trace.count("sdk-create") == 1 and not c.resources
    assert "startup-continued" not in c.p.trace


@pytest.mark.asyncio
async def test_stop_during_sdk_create_still_retains_returned_resource_fact(tmp_path, monkeypatch):
    c = _case(tmp_path, monkeypatch)

    def create(*_):
        c.p.trace.append("sdk-create")
        c.p.stopping.set()

    monkeypatch.setattr(c.p.delegate, "_create_workload", create)
    await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    assert c.p.stopping.is_set() and len(c.resources) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift",
    (
        None,
        "uid",
        "secret_uid",
        "template",
        "token",
        "cluster",
        "ca",
        "image",
        "namespace",
        "legacy",
    ),
)
async def test_restore_inspection_is_exact_and_has_no_creation_or_deletion(
    tmp_path, monkeypatch, drift
):
    c = _case(tmp_path, monkeypatch)
    await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    record = SimpleNamespace(managed_preparation=c.p.recorded[0], managed_resources=c.resources[0])
    if drift == "uid":
        c.workload["metadata"]["uid"] = str(UUID(int=3))
    elif drift == "secret_uid":
        c.secret["metadata"]["uid"] = str(UUID(int=4))
    elif drift == "template":
        c.template["metadata"]["annotations"] = {"unexpected": "drift"}
    elif drift == "token":
        c.secret["data"][HOST_TOKEN_ENV_VAR] = base64.b64encode(b"foreign").decode()
    elif drift == "cluster":
        c.p.configuration.host = "https://foreign.test"
    elif drift == "ca":
        c.p.ca.write_bytes(b"different-public-test-ca")
    elif drift == "image":
        c.p.delegate._image_ref = "foreign/image"
    elif drift == "namespace":
        c.p.delegate._namespace = "foreign"
    elif drift == "legacy":
        record.managed_resources = None
    c.p.trace.clear()
    if drift is None:
        assert inspect_managed_resources(c.p.deployment, record) == record.managed_resources
    else:
        with pytest.raises(RunnerControlError):
            inspect_managed_resources(c.p.deployment, record)
    assert "sdk-create" not in c.p.trace and "startup-continued" not in c.p.trace


@pytest.mark.asyncio
async def test_resource_uid_fact_survives_private_reopen_without_becoming_stop_proof(
    controller_case,
):
    c = controller_case
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    c.executor._put(active, managed_preparation=_reference())
    path = c.journal.root / f"{c.lease.run_id}.json"
    v3 = json.loads(path.read_bytes())
    assert v3["schema_version"] == 3 and "managed_resources" not in v3["record"]
    c.executor._put(active, managed_resources=_resources())
    before, original = path.read_bytes(), c.journal.read(c.lease.run_id)
    assert json.loads(before)["schema_version"] == 4
    with pytest.raises(InteractiveRecoveryError):
        physical_recovery_proof_sha256(original)
    for changed in (None, _resources(workload_uid=str(UUID(int=3)))):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(original, managed_resources=changed))
    assert path.read_bytes() == before
    c.executor._active.pop(c.lease.run_id).meter.close(timeout_seconds=0)
    c.journal.close()
    restored = InteractiveRecoveryJournal(c.journal.root)
    try:
        assert restored.read(c.lease.run_id) == original
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        restored.close()


@pytest.mark.asyncio
async def test_resource_fact_cannot_be_attached_without_its_original_preparation(controller_case):
    c = controller_case
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    with pytest.raises(InteractiveRecoveryError):
        c.executor._put(active, managed_resources=_resources())
    assert c.journal.read(c.lease.run_id).managed_resources is None


@pytest.mark.parametrize(
    "field,value",
    (
        ("workload_uid", "fabricated"),
        ("workload_uid", UUID(int=1)),
        ("token_secret_uid", None),
        ("token_secret_uid", str(UUID(int=1))),
        ("pod_template_sha256", "not-a-template-hash"),
        ("pod_template_sha256", None),
        ("host_token_sha256", "not-a-token-hash"),
        ("host_token_sha256", {}),
    ),
)
def test_invalid_created_resource_binding_fails_closed(field, value):
    with pytest.raises(InteractiveRecoveryError):
        _resources(**{field: value})


@pytest.mark.asyncio
@pytest.mark.parametrize("token", (None, "foreign-token", 123))
async def test_missing_or_foreign_host_credential_never_creates_or_checkpoints_resources(
    tmp_path, monkeypatch, token
):
    c = _case(tmp_path, monkeypatch)
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=token)
    assert "sdk-create" not in c.p.trace and not c.resources and not c.p.recorded


@pytest.mark.asyncio
async def test_v4_fact_cannot_be_downgraded_smuggled_or_partially_decoded(controller_case):
    c = controller_case
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    c.executor._put(active, managed_preparation=_reference())
    c.executor._put(active, managed_resources=_resources())
    path = c.journal.root / f"{c.lease.run_id}.json"
    before = path.read_bytes()
    try:
        for corruption in ("v1", "v2", "v3", "missing", "uid", "extra", "unstarted"):
            doc = json.loads(before)
            if corruption in {"v1", "v2", "v3"}:
                doc["schema_version"] = int(corruption[1])
                if corruption == "v1":
                    doc.pop("record_type")
            elif corruption == "missing":
                doc["record"].pop("managed_resources")
            elif corruption == "uid":
                doc["record"]["managed_resources"]["workload_uid"] = "fabricated"
            elif corruption == "extra":
                doc["record"]["managed_resources"]["terminated"] = True
            else:
                doc["record_type"] = "unstarted"
            path.write_text(json.dumps(doc))
            with pytest.raises(InteractiveRecoveryError):
                c.journal.read(c.lease.run_id)
    finally:
        path.write_bytes(before)
    assert c.journal.read(c.lease.run_id) == active.record


@pytest.mark.asyncio
async def test_external_run_cannot_forge_a_created_resource_fact(controller_case, monkeypatch):
    c = controller_case
    original = c.physical.prepare

    async def prepare(actual, **values):
        with pytest.raises(RunnerControlError):
            await values["on_resources"](_resources())
        return await original(actual, **values)

    monkeypatch.setattr(c.physical, "prepare", prepare)
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    assert c.journal.read(c.lease.run_id).managed_resources is None
