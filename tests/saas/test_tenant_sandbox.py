from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from typing import Any
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest

from omnigent.db.db_models import workspace_scope
from omnigent.db.utils import now_epoch
from omnigent.stores.host_store import HostStore
from saas.compatibility.runtime_partition import RuntimeContext, bind_runtime_context
from saas.production.tenant_model_keys import TenantModelKeyBinding
from saas.production.tenant_sandbox import parse_tenant_sandbox_config

WORKSPACE_ENV = "OMNIGENT_HOST_WORKSPACE_ID"
TENANT_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID"


def _runtime(workspace_id: int = 91) -> RuntimeContext:
    return RuntimeContext(
        actor_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        runtime_partition_id=uuid4(),
        placement_id=uuid4(),
        placement_generation=1,
        binding_generation=1,
        data_region="test",
        physical_workspace_id=workspace_id,
        runtime_user_key="synthetic-user",
        runtime_type="omnigent",
        source_revision="test-revision",
        adapter_contract_version="0.2.0",
        trace_id="tenant-launch-test",
    )


def _config() -> dict[str, Any]:
    return {
        "server_url": "http://runtime.example.test",
        "providers": [{"provider": "agent_sandbox"}, {"provider": "kubernetes"}],
        "kubernetes": {
            "env": [WORKSPACE_ENV, TENANT_ENV],
            "namespace": "test-sandboxes",
            "image": "example.test/host@sha256:" + "a" * 64,
        },
    }


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_launch_identity_comes_from_authorized_runtime_not_global_env(monkeypatch, provider):
    monkeypatch.setenv(WORKSPACE_ENV, "17")
    monkeypatch.setenv(TENANT_ENV, str(UUID(int=17)))
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    runtime = _runtime()
    with bind_runtime_context(runtime):
        launcher = config.for_provider(provider).launcher_factory()
        assert launcher._resolve_sandbox_env() == {
            WORKSPACE_ENV: "91",
            TENANT_ENV: str(runtime.tenant_id),
        }


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_ambient_identity_is_not_required_or_modified(monkeypatch, provider):
    monkeypatch.delenv(WORKSPACE_ENV, raising=False)
    monkeypatch.delenv(TENANT_ENV, raising=False)
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    with bind_runtime_context(_runtime()):
        launcher = config.for_provider(provider).launcher_factory()
        assert launcher._resolve_sandbox_env()[WORKSPACE_ENV] == "91"
    assert WORKSPACE_ENV not in os.environ and TENANT_ENV not in os.environ


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_context_free_factory_can_cleanup_but_cannot_launch(monkeypatch, provider):
    monkeypatch.setenv(WORKSPACE_ENV, "17")
    monkeypatch.setenv(TENANT_ENV, str(UUID(int=17)))
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    launcher = config.for_provider(provider).launcher_factory()
    assert callable(launcher.terminate)
    with pytest.raises(RuntimeError, match="runtime context is not bound"):
        launcher._resolve_sandbox_env()


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_machine_route_hint_without_runtime_cannot_launch(provider):
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    with workspace_scope(91):
        with pytest.raises(RuntimeError, match="runtime context is not bound"):
            config.for_provider(provider).launcher_factory()._resolve_sandbox_env()


@pytest.mark.parametrize("workspace_id", [0, -1, True])
def test_invalid_workspace_is_rejected(workspace_id):
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    with bind_runtime_context(_runtime(workspace_id)):
        with pytest.raises(ValueError, match="Sandbox runtime identity"):
            config.default.launcher_factory()._resolve_sandbox_env()


def test_mismatched_workspace_context_is_rejected():
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    with bind_runtime_context(_runtime()), workspace_scope(92):
        with pytest.raises(ValueError, match="Sandbox runtime identity"):
            config.default.launcher_factory()._resolve_sandbox_env()


def test_empty_tenant_is_rejected():
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    with bind_runtime_context(replace(_runtime(), tenant_id=UUID(int=0))):
        with pytest.raises(ValueError, match="Sandbox runtime identity"):
            config.default.launcher_factory()._resolve_sandbox_env()


def test_concurrent_background_launches_keep_distinct_tenant_identity(monkeypatch):
    monkeypatch.setenv(WORKSPACE_ENV, "17")
    monkeypatch.setenv(TENANT_ENV, str(UUID(int=17)))
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    runtimes = [_runtime(91), _runtime(92)]

    async def scenario():
        ready = asyncio.Event()

        async def launch(provider):
            await ready.wait()
            launcher = config.for_provider(provider).launcher_factory()
            return await asyncio.to_thread(launcher._resolve_sandbox_env)

        tasks = []
        for runtime, provider in zip(runtimes, ["agent_sandbox", "kubernetes"], strict=True):
            with bind_runtime_context(runtime):
                tasks.append(asyncio.create_task(launch(provider)))
        ready.set()
        return await asyncio.gather(*tasks)

    results = asyncio.run(scenario())
    assert results == [
        {WORKSPACE_ENV: str(r.physical_workspace_id), TENANT_ENV: str(r.tenant_id)}
        for r in runtimes
    ]
    assert os.environ[WORKSPACE_ENV] == "17"
    assert os.environ[TENANT_ENV] == str(UUID(int=17))


def test_disabled_sandboxes_remain_disabled():
    assert parse_tenant_sandbox_config(None) is None


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_enabled_tenant_mounts_only_its_own_model_key(tmp_path, provider):
    runtime = _runtime()
    binding = TenantModelKeyBinding(
        runtime.tenant_id,
        91,
        f"omnigent-sandbox-model-{runtime.tenant_id.hex}",
        tmp_path / "key",
    )
    raw = _config()
    raw["kubernetes"]["secret_mounts"] = [
        {
            "secret_name": "legacy-key",
            "mount_path": "/credentials/omnigent-platform-model",
        }
    ]
    config = parse_tenant_sandbox_config(
        raw, model_bindings=(binding,), legacy_tenant_id=UUID(int=17)
    )
    assert config is not None
    with bind_runtime_context(runtime):
        launcher = config.for_provider(provider).launcher_factory()
        assert launcher._secret_mounts == [
            {
                "secret_name": binding.sandbox_secret_name,
                "mount_path": "/credentials/omnigent-platform-model",
            }
        ]
        assert launcher._resolve_sandbox_env()[TENANT_ENV] == str(runtime.tenant_id)
    with bind_runtime_context(replace(runtime, tenant_id=UUID(int=17))):
        legacy = config.for_provider(provider).launcher_factory()
        assert legacy._secret_mounts == raw["kubernetes"]["secret_mounts"]
    with bind_runtime_context(_runtime()):
        with pytest.raises(ValueError, match="no model authority"):
            config.for_provider(provider).launcher_factory()
    with bind_runtime_context(replace(runtime, physical_workspace_id=92)):
        with pytest.raises(ValueError, match="workspace is invalid"):
            config.for_provider(provider).launcher_factory()
    with bind_runtime_context(replace(runtime, tenant_id=UUID(int=17))):
        with pytest.raises(ValueError, match="runtime identity"):
            launcher._resolve_sandbox_env()
    assert raw["kubernetes"]["secret_mounts"][0]["secret_name"] == "legacy-key"


@pytest.mark.parametrize("env", [[], [WORKSPACE_ENV], [WORKSPACE_ENV, TENANT_ENV, "HOME"]])
def test_unreviewed_environment_is_rejected(env):
    raw = _config()
    raw["kubernetes"]["env"] = env
    with pytest.raises(ValueError, match="Sandbox runtime identity environment"):
        parse_tenant_sandbox_config(raw)


def test_unreviewed_provider_is_rejected():
    raw = _config()
    raw["providers"] = [{"provider": "modal"}]
    with pytest.raises(ValueError, match="Sandbox provider is not reviewed"):
        parse_tenant_sandbox_config(raw)


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_actual_launch_manifest_uses_tenant_identity_without_external_calls(monkeypatch, provider):
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    launcher = config.for_provider(provider).launcher_factory()
    core = Mock()
    manifests = []
    monkeypatch.setattr(launcher, "_load_core", lambda: core)
    monkeypatch.setattr(
        launcher, "_create_workload", lambda ns, body: manifests.append((ns, body))
    )
    monkeypatch.setattr(launcher, "_wait_for_pod_running", lambda *_: None)
    monkeypatch.setattr(launcher, "_close_clients", lambda: None)
    runtime = _runtime()
    with bind_runtime_context(runtime):
        workspace = launcher.start_host(
            "test-sandbox",
            token="synthetic-launch-token",
            host_id=uuid4().hex,
            host_name="synthetic-host",
            server_url="http://runtime.example.test",
        )
    assert workspace == "/home/omnigent/workspace"
    assert len(manifests) == 1
    namespace, manifest = manifests[0]
    assert namespace == "test-sandboxes"
    host = manifest["spec"]["template"]["spec"]["containers"][0]
    identity = {
        item["name"]: item["value"]
        for item in host["env"]
        if item["name"] in {WORKSPACE_ENV, TENANT_ENV}
    }
    assert identity == {WORKSPACE_ENV: "91", TENANT_ENV: str(runtime.tenant_id)}
    assert host["securityContext"]["allowPrivilegeEscalation"] is False
    assert host["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    core.create_namespaced_secret.assert_called_once()


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_missing_identity_fails_before_any_secret_or_workload_creation(monkeypatch, provider):
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    launcher = config.for_provider(provider).launcher_factory()
    external = Mock(side_effect=AssertionError("unexpected external effect"))
    monkeypatch.setattr(launcher, "_load_core", external)
    monkeypatch.setattr(launcher, "_create_workload", external)
    with pytest.raises(RuntimeError, match="runtime context is not bound"):
        launcher.start_host(
            "test-sandbox",
            token="synthetic",
            host_id=uuid4().hex,
            host_name="test",
            server_url="http://runtime.example.test",
        )
    external.assert_not_called()


@pytest.mark.parametrize("provider", ["agent_sandbox", "kubernetes"])
def test_scoped_identity_resolves_real_host_store_and_rejects_wrong_workspace(db_uri, provider):
    runtime = _runtime()
    config = parse_tenant_sandbox_config(_config())
    assert config is not None
    store = HostStore(db_uri)
    host_id = uuid4().hex
    with bind_runtime_context(runtime):
        store.register_managed_host(
            host_id=host_id,
            name="synthetic-host",
            user_id=runtime.runtime_user_key,
            token="synthetic-launch-token",
            provider=provider,
            sandbox_id="test-sandbox",
            token_expires_at=now_epoch() + 60,
        )
        env = config.for_provider(provider).launcher_factory()._resolve_sandbox_env()
    with workspace_scope(int(env[WORKSPACE_ENV])):
        host = store.resolve_launch_token(host_id, "synthetic-launch-token")
        assert host is not None and host.user_id == runtime.runtime_user_key
        assert store.resolve_launch_token(host_id, "wrong-token") is None
    with workspace_scope(17):
        assert store.resolve_launch_token(host_id, "synthetic-launch-token") is None
