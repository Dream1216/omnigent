from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID, uuid4

import click
import pytest

from omnigent.db.db_models import workspace_scope
from saas.compatibility.runtime_partition import bind_runtime_context
from saas.production.aliyun_sandbox import (
    ALIYUN_API_URL,
    ALIYUN_DOMAIN,
    AliyunSandboxLauncher,
    AliyunSandboxScope,
)
from tests.saas.test_tenant_sandbox import _runtime


@pytest.fixture
def cloud(tmp_path, monkeypatch):
    runtime = _runtime()
    scope = AliyunSandboxScope(runtime.tenant_id, runtime.physical_workspace_id)
    key = tmp_path / "api-key"
    key.write_text("e2b_" + "a" * 32 + "\n")
    key.chmod(0o600)
    handle = Mock(sandbox_id="sbx-test-1234")
    handle.get_info.return_value = SimpleNamespace(metadata=scope.metadata())
    sdk = Mock()
    sdk.create.return_value = sdk.connect.return_value = handle
    monkeypatch.setattr("e2b.Sandbox", sdk)
    launcher = AliyunSandboxLauncher(template="host-template", credential_file=key, scope=scope)
    return SimpleNamespace(
        runtime=runtime, scope=scope, key=key, handle=handle, sdk=sdk, launcher=launcher
    )


def test_create_ignores_ambient_cloud_credentials_and_runtime_identity(cloud, monkeypatch):
    for k, v in {
        "E2B_API_KEY": "wrong",
        "E2B_API_URL": "https://wrong.example.test",
        "E2B_DOMAIN": "wrong.example.test",
        "OMNIGENT_E2B_MAX_LIFETIME_S": "invalid",
        "OMNIGENT_E2B_TEMPLATE": "wrong-template",
        "OMNIGENT_E2B_SANDBOX_ENV": "PLATFORM_ADMIN_KEY",
        "PLATFORM_ADMIN_KEY": "must-stay-on-server",
        "OMNIGENT_HOST_WORKSPACE_ID": "999",
    }.items():
        monkeypatch.setenv(k, v)
    with bind_runtime_context(cloud.runtime):
        assert cloud.launcher.provision("managed-123") == "sbx-test-1234"
    values = cloud.sdk.create.call_args.kwargs
    assert values == {
        "template": "host-template",
        "timeout": 1800,
        "metadata": {**cloud.scope.metadata(), "omnigent-name": "managed-123"},
        "envs": {
            "OMNIGENT_HOST_WORKSPACE_ID": "91",
            "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID": str(cloud.runtime.tenant_id),
        },
        "api_key": "e2b_" + "a" * 32,
        "api_url": ALIYUN_API_URL,
        "domain": ALIYUN_DOMAIN,
        "request_timeout": 45,
    }


def test_launch_requires_runtime_even_with_explicit_cleanup_scope(cloud):
    with pytest.raises(RuntimeError, match="runtime context is not bound"):
        cloud.launcher.provision("managed-test")
    cloud.sdk.create.assert_not_called()


@pytest.mark.parametrize("change", ["tenant", "workspace", "database"])
def test_foreign_context_cannot_manage_or_create(cloud, change):
    runtime = cloud.runtime
    if change == "tenant":
        runtime = replace(runtime, tenant_id=uuid4())
    elif change == "workspace":
        runtime = replace(runtime, physical_workspace_id=92)
    with (
        bind_runtime_context(runtime),
        workspace_scope(92 if change == "database" else runtime.physical_workspace_id),
    ):
        with pytest.raises(ValueError, match=r"identity|workspace"):
            cloud.launcher.provision("managed-test")
        with pytest.raises(ValueError, match=r"identity|workspace"):
            cloud.launcher.terminate("sbx-test-1234")
    cloud.sdk.create.assert_not_called()
    cloud.sdk.connect.assert_not_called()


@pytest.mark.parametrize("field", ["omnigent-provider", "omnigent-tenant", "omnigent-workspace"])
def test_foreign_sandbox_is_not_executed_renewed_or_killed(cloud, field):
    metadata = cloud.scope.metadata()
    metadata[field] = "foreign"
    cloud.handle.get_info.return_value = SimpleNamespace(metadata=metadata)
    for action in (
        lambda: cloud.launcher.run("sbx-test-1234", "id"),
        lambda: cloud.launcher.keep_alive("sbx-test-1234"),
        lambda: cloud.launcher.terminate("sbx-test-1234"),
    ):
        with pytest.raises(ValueError, match="ownership"):
            action()
    cloud.handle.commands.run.assert_not_called()
    cloud.handle.set_timeout.assert_not_called()
    cloud.handle.kill.assert_not_called()


def test_cached_handles_are_still_ownership_checked(cloud):
    with bind_runtime_context(cloud.runtime):
        sandbox_id = cloud.launcher.provision("managed-test")
    cloud.handle.get_info.return_value = SimpleNamespace(metadata={})
    with pytest.raises(ValueError, match="ownership"):
        cloud.launcher.terminate(sandbox_id)
    cloud.handle.kill.assert_not_called()


def test_reconnect_renewal_and_cleanup_keep_explicit_endpoint_and_current_key(cloud):
    cloud.launcher.keep_alive("sbx-test-1234")
    values = cloud.sdk.connect.call_args.kwargs
    assert values["api_url"] == ALIYUN_API_URL and values["domain"] == ALIYUN_DOMAIN
    assert cloud.handle.set_timeout.call_args.args == (1800,)
    cloud.key.write_text("e2b_" + "b" * 32)
    cloud.launcher.terminate("sbx-test-1234")
    assert cloud.handle.get_info.call_args.kwargs["api_key"] == "e2b_" + "b" * 32
    assert cloud.handle.kill.call_args.kwargs == {**values, "api_key": "e2b_" + "b" * 32}
    assert not cloud.launcher._sandboxes


def test_already_absent_sandbox_cleanup_is_idempotent(cloud):
    from e2b.exceptions import SandboxNotFoundException

    cloud.sdk.connect.side_effect = SandboxNotFoundException("already gone")
    cloud.launcher.terminate("sbx-test-1234")
    cloud.handle.kill.assert_not_called()


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o660])
def test_shared_key_files_fail_before_sdk_call(cloud, mode):
    cloud.key.chmod(mode)
    with pytest.raises(ValueError, match="authority file"):
        cloud.launcher.terminate("sbx-test-1234")
    cloud.sdk.connect.assert_not_called()


def test_missing_and_symlink_key_files_are_rejected(cloud, tmp_path):
    cloud.key.unlink()
    with pytest.raises(ValueError, match="authority file"):
        cloud.launcher.prepare()
    other = tmp_path / "another-key"
    other.write_text("e2b_" + "a" * 32)
    other.chmod(0o600)
    cloud.key.symlink_to(other)
    with pytest.raises(ValueError, match="authority file"):
        cloud.launcher.prepare()
    cloud.sdk.connect.assert_not_called()


@pytest.mark.parametrize("lifetime", [True, 0, -1, 59, 3601, 86400, "1800"])
def test_unqualified_lifetimes_are_rejected(cloud, lifetime):
    with pytest.raises(ValueError, match="configuration"):
        AliyunSandboxLauncher(
            template="host-template",
            credential_file=cloud.key,
            scope=cloud.scope,
            lifetime_s=lifetime,
        )


@pytest.mark.parametrize("workspace", [True, 0, -1, 2**63])
def test_invalid_scope_cannot_be_constructed(workspace):
    with pytest.raises(ValueError, match="identity"):
        AliyunSandboxScope(UUID(int=1), workspace)


@pytest.mark.parametrize("identifier", ["../other", "a/b", "a?secret=x", "a\nheader", ""])
def test_invalid_resource_identifiers_are_rejected_before_sdk(cloud, identifier):
    with pytest.raises(ValueError, match="identifier"):
        cloud.launcher.terminate(identifier)
    cloud.sdk.connect.assert_not_called()


def test_sdk_error_does_not_echo_management_credential(cloud):
    from e2b.exceptions import AuthenticationException

    cloud.sdk.create.side_effect = AuthenticationException("e2b_" + "a" * 32)
    with bind_runtime_context(cloud.runtime):
        with pytest.raises(click.ClickException) as raised:
            cloud.launcher.provision("managed-test")
    assert "e2b_" not in str(raised.value)
    assert raised.value.__suppress_context__


def test_scope_can_only_be_resolved_from_valid_runtime():
    with pytest.raises(RuntimeError, match="runtime context is not bound"):
        AliyunSandboxScope.from_runtime()
    with bind_runtime_context(_runtime()) as runtime:
        assert AliyunSandboxScope.from_runtime() == AliyunSandboxScope(runtime.tenant_id, 91)
