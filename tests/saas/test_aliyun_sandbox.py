from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
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
    clock = SimpleNamespace(now=datetime(2026, 10, 31, 0, 0, tzinfo=UTC))
    monkeypatch.setattr("saas.production.aliyun_sandbox._now", lambda: clock.now)
    metadata = {**scope.metadata(), "omnigent-lifetime-seconds": "1800"}
    info = SimpleNamespace(
        sandbox_id="sbx-test-1234", metadata=metadata, started_at=clock.now, state="running"
    )
    handle = Mock(sandbox_id="sbx-test-1234")
    handle.commands.run.return_value = SimpleNamespace(stdout="ok", stderr="", exit_code=0)
    sdk = Mock()
    sdk.create.return_value = sdk.connect.return_value = handle
    monkeypatch.setattr("e2b.Sandbox", sdk)
    reader = Mock(return_value=info)
    attach = Mock(return_value=handle)
    monkeypatch.setattr("saas.production.aliyun_sandbox.read_sandbox_details", reader)
    monkeypatch.setattr("saas.production.aliyun_sandbox.attach_running_sandbox", attach)
    launcher = AliyunSandboxLauncher(template="host-template", credential_file=key, scope=scope)
    return SimpleNamespace(
        runtime=runtime,
        scope=scope,
        key=key,
        handle=handle,
        sdk=sdk,
        launcher=launcher,
        clock=clock,
        info=info,
        reader=reader,
        attach=attach,
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
        "metadata": {
            **cloud.scope.metadata(),
            "omnigent-name": "managed-123",
            "omnigent-lifetime-seconds": "1800",
        },
        "envs": {
            "OMNIGENT_HOST_WORKSPACE_ID": "91",
            "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID": str(cloud.runtime.tenant_id),
        },
        "api_key": "e2b_" + "a" * 32,
        "api_url": ALIYUN_API_URL,
        "domain": ALIYUN_DOMAIN,
        "request_timeout": 45,
        "debug": False,
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
    cloud.info.metadata = metadata
    for action in (
        lambda: cloud.launcher.run("sbx-test-1234", "id"),
        lambda: cloud.launcher.keep_alive("sbx-test-1234"),
        lambda: cloud.launcher.terminate("sbx-test-1234"),
    ):
        with pytest.raises(ValueError, match="ownership"):
            action()
    cloud.handle.commands.run.assert_not_called()
    cloud.sdk.connect.assert_not_called()
    cloud.attach.assert_not_called()
    cloud.handle.set_timeout.assert_not_called()
    cloud.sdk.kill.assert_not_called()


def test_cached_handles_are_still_ownership_checked(cloud):
    with bind_runtime_context(cloud.runtime):
        sandbox_id = cloud.launcher.provision("managed-test")
    cloud.info.metadata = {}
    with pytest.raises(ValueError, match="ownership"):
        cloud.launcher.terminate(sandbox_id)
    cloud.sdk.kill.assert_not_called()


def test_reconnect_renewal_and_cleanup_keep_explicit_endpoint_and_current_key(cloud):
    cloud.launcher.keep_alive("sbx-test-1234")
    cloud.sdk.connect.assert_not_called()
    assert cloud.launcher.run("sbx-test-1234", "id").stdout == "ok"
    cloud.sdk.connect.assert_not_called()
    values = cloud.attach.call_args.args[1]
    assert values["api_url"] == ALIYUN_API_URL and values["domain"] == ALIYUN_DOMAIN
    cloud.handle.set_timeout.assert_not_called()
    cloud.key.write_text("e2b_" + "b" * 32)
    cloud.launcher.terminate("sbx-test-1234")
    assert cloud.reader.call_args.args[1]["api_key"] == "e2b_" + "b" * 32
    assert cloud.sdk.kill.call_args.args == ("sbx-test-1234",)
    assert cloud.sdk.kill.call_args.kwargs == {**values, "api_key": "e2b_" + "b" * 32}
    assert not cloud.launcher._sandboxes


def test_already_absent_sandbox_cleanup_is_idempotent(cloud):
    from e2b.exceptions import SandboxNotFoundException

    cloud.reader.side_effect = SandboxNotFoundException("already gone")
    cloud.launcher.terminate("sbx-test-1234")
    cloud.sdk.connect.assert_not_called()
    cloud.sdk.kill.assert_not_called()


def test_heartbeats_do_not_extend_the_cloud_creation_deadline(cloud):
    started = cloud.clock.now
    for elapsed in (0, 600, 1798):
        cloud.clock.now = started + timedelta(seconds=elapsed)
        cloud.launcher.keep_alive("sbx-test-1234")
    cloud.clock.now = started + timedelta(seconds=1800)
    with pytest.raises(click.ClickException, match="absolute lifetime"):
        cloud.launcher.keep_alive("sbx-test-1234")
    cloud.sdk.connect.assert_not_called()
    cloud.handle.set_timeout.assert_not_called()


def test_restart_and_longer_configuration_do_not_renew_an_existing_launch(cloud):
    restarted = AliyunSandboxLauncher(
        template="host-template", credential_file=cloud.key, scope=cloud.scope, lifetime_s=3600
    )
    cloud.clock.now += timedelta(seconds=1800)
    with pytest.raises(click.ClickException):
        restarted.run("sbx-test-1234", "id")
    cloud.sdk.connect.assert_not_called()
    cloud.handle.commands.run.assert_not_called()
    restarted.terminate("sbx-test-1234")
    cloud.sdk.kill.assert_called_once()


@pytest.mark.parametrize("lifetime", [None, True, 1800, "", "01800", "59", "3601", "1e3"])
def test_missing_or_invalid_lifetime_evidence_prevents_connect_and_execution(cloud, lifetime):
    cloud.info.metadata["omnigent-lifetime-seconds"] = lifetime
    with pytest.raises(ValueError, match="lifetime evidence"):
        cloud.launcher.run("sbx-test-1234", "id")
    cloud.sdk.connect.assert_not_called()
    cloud.handle.commands.run.assert_not_called()
    cloud.launcher.terminate("sbx-test-1234")
    cloud.sdk.kill.assert_called_once()


@pytest.mark.parametrize("state", ["paused", "unknown", None])
def test_nonrunning_instance_is_not_resumed_even_for_cleanup(cloud, state):
    cloud.info.state = state
    with pytest.raises(click.ClickException):
        cloud.launcher.run("sbx-test-1234", "id")
    cloud.sdk.connect.assert_not_called()
    cloud.launcher.terminate("sbx-test-1234")
    cloud.sdk.kill.assert_called_once()
    cloud.sdk.connect.assert_not_called()


@pytest.mark.parametrize(
    "started", [None, "2026-10-31", datetime(2026, 10, 31, tzinfo=UTC).replace(tzinfo=None)]
)
def test_untrusted_start_time_fails_before_connection(cloud, started):
    cloud.info.started_at = started
    with pytest.raises(ValueError, match="lifetime evidence"):
        cloud.launcher.keep_alive("sbx-test-1234")
    cloud.sdk.connect.assert_not_called()


def test_clock_skew_cannot_create_an_unbounded_lifetime(cloud):
    cloud.info.started_at += timedelta(seconds=31)
    with pytest.raises(ValueError, match="start time"):
        cloud.launcher.run("sbx-test-1234", "id")
    cloud.sdk.connect.assert_not_called()


def test_readonly_lookup_must_return_the_requested_resource(cloud):
    cloud.info.sandbox_id = "other-instance"
    with pytest.raises(ValueError, match="ownership"):
        cloud.launcher.terminate("sbx-test-1234")
    cloud.sdk.connect.assert_not_called()
    cloud.sdk.kill.assert_not_called()


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
