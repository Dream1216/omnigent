from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from omnigent.db.db_models import workspace_scope
from saas.compatibility.runtime_partition import bind_runtime_context
from saas.production.aliyun_model_lease import HostModelLeaseAuthority
from saas.production.aliyun_sandbox import AliyunSandboxScope
from saas.production.aliyun_tenant_sandbox import AliyunManagedSandbox
from saas.production.tenant_sandbox import parse_tenant_sandbox_config
from tests.saas.test_aliyun_sandbox import cloud as cloud
from tests.saas.test_production_server import _reviewed_production_sandbox_config
from tests.saas.test_tenant_sandbox import _config


def _settings(cloud):
    return AliyunManagedSandbox(
        template="host-template",
        credential_file=cloud.key,
        server_url="https://control.invalid",
        model_gateway_url="https://control.invalid/platform-model/v1",
        scopes=(cloud.scope,),
        model_leases=HostModelLeaseAuthority(b"l" * 32),
    )


def _deployment(cloud, *, aliyun_only=False, **changes):
    settings = replace(_settings(cloud), **changes)
    raw = _reviewed_production_sandbox_config(aliyun_only=True) if aliyun_only else _config()
    if aliyun_only:
        raw["server_url"] = settings.server_url
    parsed = parse_tenant_sandbox_config(raw, aliyun=settings)
    assert parsed is not None
    return parsed


@pytest.mark.parametrize("aliyun_only", [False, True])
def test_opt_in_adds_aliyun_without_replacing_the_reviewed_existing_providers(
    cloud, monkeypatch, aliyun_only
):
    monkeypatch.setenv("OMNIGENT_E2B_MAX_LIFETIME_S", "invalid-global-default")
    parsed = _deployment(cloud, aliyun_only=aliyun_only)
    assert parsed.launchable_providers() == (
        ("e2b",) if aliyun_only else ("agent_sandbox", "kubernetes", "e2b")
    )
    assert parsed.default.provider == ("e2b" if aliyun_only else "agent_sandbox")
    entry = parsed.for_provider("e2b")
    assert entry.server_url == "https://control.invalid" and entry.token_ttl_s == 5400
    if aliyun_only:
        assert entry.host_config and "platform-deepseek" in entry.host_config["providers"]
        assert parsed.reaper.enabled and parsed.reaper.terminate_after_offline_days == 7
        assert parsed.for_provider("kubernetes") is None
    else:
        assert parsed.for_provider("kubernetes").server_url == "http://runtime.example.test"


def test_public_capability_discovery_has_no_default_tenant_or_cloud_io(cloud):
    with workspace_scope(0):
        parsed = _deployment(cloud)
        caps = parsed.provider_ui_capabilities()
        assert caps["e2b"]["multi_repo"] is True
        with pytest.raises(ValueError, match="configured workspace"):
            _ = parsed.for_provider("e2b").launcher_factory().scope
    cloud.sdk.create.assert_not_called()
    cloud.sdk.connect.assert_not_called()


def test_authorized_runtime_is_captured_before_async_launch(cloud):
    parsed = _deployment(cloud)
    with bind_runtime_context(cloud.runtime):
        launcher = parsed.for_provider("e2b").launcher_factory()
    with bind_runtime_context(replace(cloud.runtime, tenant_id=uuid4())):
        with pytest.raises(ValueError, match="identity"):
            launcher.provision("managed-test")
    cloud.sdk.create.assert_not_called()


@pytest.mark.parametrize("aliyun_only", [False, True])
@pytest.mark.parametrize("change", ["tenant", "workspace"])
def test_unlisted_runtime_is_denied_before_cloud_creation(cloud, change, aliyun_only):
    parsed = _deployment(cloud, aliyun_only=aliyun_only)
    runtime = replace(
        cloud.runtime,
        **({"tenant_id": uuid4()} if change == "tenant" else {"physical_workspace_id": 92}),
    )
    with bind_runtime_context(runtime):
        launcher = parsed.for_provider("e2b").launcher_factory()
        assert launcher.capabilities.managed_launch
        with pytest.raises(ValueError, match="not admitted"):
            launcher.provision("managed-test")
    cloud.sdk.create.assert_not_called()


def test_persisted_cleanup_workspace_selects_only_its_configured_tenant(cloud):
    parsed = _deployment(cloud)
    with workspace_scope(cloud.scope.workspace_id):
        launcher = parsed.for_provider("e2b").launcher_factory()
        assert launcher.scope == cloud.scope
        launcher.terminate("sbx-test-1234")
    cloud.sdk.kill.assert_called_once()
    cloud.sdk.connect.assert_not_called()


def test_wrong_tenant_sandbox_metadata_is_rejected_even_in_a_valid_cleanup_workspace(cloud):
    other = AliyunSandboxScope(uuid4(), 92)
    parsed = _deployment(cloud, scopes=(cloud.scope, other))
    with workspace_scope(92):
        launcher = parsed.for_provider("e2b").launcher_factory()
        assert launcher.scope == other
        with pytest.raises(ValueError, match="ownership"):
            launcher.terminate("sbx-test-1234")
    cloud.sdk.kill.assert_not_called()


@pytest.mark.parametrize("aliyun_only", [False, True])
def test_cleanup_scope_never_admits_creation_without_runtime_context(cloud, aliyun_only):
    parsed = _deployment(cloud, aliyun_only=aliyun_only)
    with workspace_scope(cloud.scope.workspace_id):
        launcher = parsed.for_provider("e2b").launcher_factory()
        with pytest.raises(RuntimeError, match="runtime context is not bound"):
            launcher.provision("managed-test")
    cloud.sdk.create.assert_not_called()


@pytest.mark.parametrize("workspace", [0, -1, 92, True])
def test_unknown_or_invalid_cleanup_workspace_cannot_select_cloud_authority(cloud, workspace):
    parsed = _deployment(cloud)
    with workspace_scope(workspace):
        launcher = parsed.for_provider("e2b").launcher_factory()
        with pytest.raises(ValueError, match="configured workspace"):
            launcher.terminate("sbx-test-1234")
    cloud.sdk.connect.assert_not_called()


def test_duplicate_scope_bindings_and_missing_legacy_profile_are_rejected(cloud):
    with pytest.raises(ValueError, match="allowlist"):
        replace(_settings(cloud), scopes=(cloud.scope, cloud.scope))
    with pytest.raises(ValueError, match="reviewed Sandbox"):
        parse_tenant_sandbox_config(None, aliyun=_settings(cloud))


@pytest.mark.parametrize("mutation", ["no_profile", "callback", "host_config", "extra_provider"])
def test_aliyun_only_requires_explicit_matching_profile(cloud, mutation):
    settings = _settings(cloud)
    raw = _reviewed_production_sandbox_config(aliyun_only=True)
    raw["server_url"] = settings.server_url
    if mutation == "no_profile":
        settings = None
    elif mutation == "callback":
        raw["server_url"] = "https://foreign.example.test"
    elif mutation == "host_config":
        raw["host_config"] = None
    else:
        raw["providers"] = [{"provider": "e2b"}, {"provider": "kubernetes"}]
    with pytest.raises(ValueError):
        parse_tenant_sandbox_config(raw, aliyun=settings)
    cloud.sdk.create.assert_not_called()
    cloud.sdk.connect.assert_not_called()
