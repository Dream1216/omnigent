"""Scripted SDK effect barriers; real K3s and provider deletion are separate proof."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from hashlib import sha256
from threading import Event
from types import SimpleNamespace

import pytest

from omnigent.onboarding.sandboxes.agent_sandbox import AgentSandboxLauncher
from omnigent.onboarding.sandboxes.agent_sandbox_warm_pool import AgentSandboxWarmPoolLauncher
from omnigent.onboarding.sandboxes.kubernetes import KubernetesSandboxLauncher
from omnigent.server.managed_hosts import (
    ManagedSandboxConfig,
    ManagedSandboxDeployment,
    _kubernetes_launcher_factory,
)
from saas.production import interactive_preparation as module
from saas.production.interactive_preparation import bind_managed_preparation
from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    InteractiveRecoveryJournal,
    ManagedPreparationBinding,
    physical_recovery_proof_sha256,
)
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http


def _reference(**changes):
    return replace(
        ManagedPreparationBinding(
            "kubernetes", "owned-runners", "owned-job", "c" * 32, "a" * 64, "b" * 64
        ),
        **changes,
    )


def _launcher(tmp_path, monkeypatch, provider="kubernetes", launcher_type=None, **options):
    kind = launcher_type or (
        KubernetesSandboxLauncher if provider == "kubernetes" else AgentSandboxLauncher
    )
    delegate = kind(
        namespace="owned-runners", image="registry.test/host@sha256:" + "b" * 64, **options
    )
    ca = tmp_path / "public-cluster-ca.pem"
    ca.write_bytes(b"public isolated CA fixture; not a credential")
    configuration = SimpleNamespace(
        host="https://cluster.test:6443",
        ssl_ca_cert=str(ca),
        verify_ssl=True,
        assert_hostname=None,
        tls_server_name=None,
    )
    delegate._api_client = SimpleNamespace(configuration=configuration)
    trace, recorded, stopping = [], [], Event()
    host = SimpleNamespace(
        host_id="c" * 32, user_id="owned-user", sandbox_provider=provider, sandbox_id="owned-job"
    )
    monkeypatch.setattr(delegate, "_load_clients", lambda: trace.append("load-config"))
    monkeypatch.setattr(delegate, "_close_clients", lambda: trace.append("close-client"))

    def create(resource, **values):
        assert len(recorded) == 1, "SDK create must follow the persisted checkpoint"
        assert recorded[0].resource_name == resource and recorded[0].host_id == values["host_id"]
        trace.append("create")
        return "/workspace"

    monkeypatch.setattr(delegate, "start_host", create)
    deployment = ManagedSandboxDeployment.single(
        ManagedSandboxConfig(
            server_url="https://next.test",
            launcher_factory=lambda: delegate,
            token_ttl_s=3600,
            provider=provider,
        )
    )

    async def checkpoint(binding):
        recorded.append(binding)
        trace.append("checkpoint")

    def wrap(callback=checkpoint):
        selected = bind_managed_preparation(
            deployment,
            provider=provider,
            host_store=SimpleNamespace(get_host=lambda _: host),
            owner="owned-user",
            checkpoint=callback,
            stopping=stopping,
            loop=asyncio.get_running_loop(),
        )
        return selected.default.launcher_factory()

    return SimpleNamespace(**locals())


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ("kubernetes", "agent_sandbox"))
async def test_official_direct_provider_factory_is_checkpointed(provider):
    fields = [
        "image",
        "env",
        "namespace",
        "secret_name",
        "service_account",
        "node_selector",
        "tolerations",
        "kubeconfig",
        "in_cluster",
        "resources",
        "pvc_mounts",
        "secret_mounts",
        "pod_ready_timeout_s",
        "runtime_class",
        "home_size_limit",
        "host_command",
    ]
    factory = _kubernetes_launcher_factory(
        agent_sandbox=provider == "agent_sandbox", **dict.fromkeys(fields)
    )
    deployment = ManagedSandboxDeployment.single(
        ManagedSandboxConfig(
            server_url="https://next.test",
            launcher_factory=factory,
            token_ttl_s=3600,
            provider=provider,
        )
    )

    async def checkpoint(_binding):
        raise AssertionError("Constructing a launcher cannot persist or create resources")

    bound = bind_managed_preparation(
        deployment,
        provider=provider,
        host_store=None,
        owner="owned-user",
        checkpoint=checkpoint,
        stopping=Event(),
        loop=asyncio.get_running_loop(),
    ).default.launcher_factory()
    expected = (
        KubernetesSandboxLauncher if provider == "kubernetes" else AgentSandboxWarmPoolLauncher
    )
    assert type(bound._delegate) is expected
    if provider == "agent_sandbox":
        assert bound._delegate._warm_pool is None


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ("kubernetes", "agent_sandbox"))
async def test_custom_launcher_subclasses_cannot_bypass_pre_create_checkpoint(
    tmp_path, monkeypatch, provider
):
    base = KubernetesSandboxLauncher if provider == "kubernetes" else AgentSandboxLauncher
    foreign = type("UnreviewedLauncher", (base,), {})
    p = _launcher(tmp_path, monkeypatch, provider, launcher_type=foreign)
    with pytest.raises(RunnerControlError):
        p.wrap()
    assert not p.trace and not p.recorded


@pytest.mark.asyncio
async def test_warm_pool_allocation_is_unavailable_before_claim_creation(tmp_path, monkeypatch):
    p = _launcher(
        tmp_path,
        monkeypatch,
        "agent_sandbox",
        launcher_type=AgentSandboxWarmPoolLauncher,
        warm_pool="owned-pool",
    )
    with pytest.raises(RunnerControlError):
        p.wrap()
    assert not p.trace and not p.recorded


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ("kubernetes", "agent_sandbox"))
async def test_actual_reserved_reference_is_checkpointed_before_scripted_sdk_create(
    tmp_path, monkeypatch, provider
):
    p = _launcher(tmp_path, monkeypatch, provider)
    assert (
        await asyncio.to_thread(p.wrap().start_host, "owned-job", host_id="c" * 32) == "/workspace"
    )
    binding = p.recorded[0]
    assert binding.provider == provider and binding.namespace == "owned-runners"
    assert (
        binding.image_reference_sha256 == sha256(p.delegate._resolve_image().encode()).hexdigest()
    )
    assert p.trace == ["load-config", "checkpoint", "create", "close-client"]
    assert "public isolated CA" not in repr(binding) and "cluster.test" not in repr(binding)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("write", "timeout", "stopped-before", "stopped-after"))
async def test_missing_checkpoint_ack_or_stop_never_reaches_sdk_create(
    tmp_path, monkeypatch, failure
):
    p = _launcher(tmp_path, monkeypatch)
    if failure == "stopped-before":
        p.stopping.set()

    async def checkpoint(binding):
        if failure == "write":
            raise OSError("isolated-checkpoint-write")
        if failure == "timeout":
            await asyncio.Event().wait()
        p.recorded.append(binding)
        if failure == "stopped-after":
            p.stopping.set()

    monkeypatch.setattr(module, "_CHECKPOINT_TIMEOUT_SECONDS", 0.03)
    with pytest.raises((RunnerControlError, OSError)):
        await asyncio.to_thread(p.wrap(checkpoint).start_host, "owned-job", host_id="c" * 32)
    assert "create" not in p.trace and p.trace[-1] == "close-client"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    (
        ("host_id", "d" * 32),
        ("user_id", "foreign-user"),
        ("sandbox_provider", "agent_sandbox"),
        ("sandbox_id", "foreign-job"),
    ),
)
async def test_foreign_or_changed_host_binding_is_not_a_create_authority(
    tmp_path, monkeypatch, field, value
):
    p = _launcher(tmp_path, monkeypatch)
    setattr(p.host, field, value)
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(p.wrap().start_host, "owned-job", host_id="c" * 32)
    assert not p.recorded and "create" not in p.trace


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ("verify_ssl", "assert_hostname"))
async def test_unverified_cluster_config_is_unavailable_before_creation(
    tmp_path, monkeypatch, field
):
    p = _launcher(tmp_path, monkeypatch)
    setattr(p.configuration, field, False)
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(p.wrap().start_host, "owned-job", host_id="c" * 32)
    assert not p.recorded and "create" not in p.trace


@pytest.mark.asyncio
async def test_private_reference_survives_reopen_is_immutable_and_is_not_a_stop_proof(
    controller_case,
):
    c = controller_case
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    legacy = json.loads((c.journal.root / f"{c.lease.run_id}.json").read_text())
    assert legacy["schema_version"] == 1 and "managed_preparation" not in legacy["record"]
    binding = _reference()
    c.executor._put(active, managed_preparation=binding)
    original = c.journal.read(c.lease.run_id)
    path = c.journal.root / f"{c.lease.run_id}.json"
    before = path.read_bytes()
    assert json.loads(before)["schema_version"] == 3
    assert not original.process_stopped and original.official_runner_id is None
    with pytest.raises(InteractiveRecoveryError):
        physical_recovery_proof_sha256(original)
    for changed in (None, _reference(resource_name="foreign-job")):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(original, managed_preparation=changed))
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
async def test_failed_private_write_does_not_advance_the_active_checkpoint(
    controller_case, monkeypatch
):
    c = controller_case
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    before = active.record

    def fail(_record):
        raise OSError("isolated-private-write")

    monkeypatch.setattr(c.journal, "put", fail)
    with pytest.raises(OSError):
        c.executor._put(active, managed_preparation=_reference())
    assert active.record == c.journal.read(c.lease.run_id) == before


@pytest.mark.parametrize(
    "field,value",
    (
        ("provider", "external"),
        ("provider", {}),
        ("namespace", "../foreign"),
        ("namespace", "x" * 64),
        ("resource_name", "foreign/job"),
        ("resource_name", True),
        ("host_id", "fabricated"),
        ("cluster_sha256", "not-a-fingerprint"),
        ("image_reference_sha256", None),
    ),
)
def test_invalid_resource_references_fail_closed(field, value):
    with pytest.raises(InteractiveRecoveryError):
        _reference(**{field: value})


@pytest.mark.asyncio
async def test_private_v3_rejects_corruption_and_legacy_smuggling(controller_case):
    c = controller_case
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    c.executor._put(active, managed_preparation=_reference())
    path = c.journal.root / f"{c.lease.run_id}.json"
    before = path.read_bytes()
    try:
        for corruption in ("v1", "v2", "bool", "unstarted", "missing", "extra", "namespace"):
            doc = json.loads(before)
            if corruption in {"v1", "v2", "bool"}:
                doc["schema_version"] = {"v1": 1, "v2": 2, "bool": True}[corruption]
                if corruption == "v1":
                    doc.pop("record_type")
            elif corruption == "unstarted":
                doc["record_type"] = "unstarted"
            elif corruption == "missing":
                doc["record"].pop("managed_preparation")
            elif corruption == "extra":
                doc["record"]["managed_preparation"]["deleted"] = True
            else:
                doc["record"]["managed_preparation"]["namespace"] = "../foreign"
            path.write_text(json.dumps(doc))
            with pytest.raises(InteractiveRecoveryError):
                c.journal.read(c.lease.run_id)
    finally:
        path.write_bytes(before)
    assert c.journal.read(c.lease.run_id) == active.record


@pytest.mark.asyncio
async def test_external_run_cannot_persist_a_managed_preparation(controller_case, monkeypatch):
    c = controller_case
    original = c.physical.prepare
    rejected = []

    async def prepare(actual, **values):
        with pytest.raises(RunnerControlError):
            await values["on_preparation"](_reference())
        rejected.append(actual.run_id)
        assert c.journal.read(actual.run_id).managed_preparation is None
        return await original(actual, **values)

    monkeypatch.setattr(c.physical, "prepare", prepare)
    assert await c.executor.execute(c.lease, cancellation=asyncio.Event()) == "succeeded"
    assert rejected == [c.lease.run_id]
    assert c.journal.read(c.lease.run_id).managed_preparation is None
