from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import click
import pytest

from omnigent.onboarding.sandboxes.base import RemoteCommandResult
from omnigent.onboarding.sandboxes.types import GitCloneOptions, RepoWorkspace
from saas.compatibility.runtime_partition import bind_runtime_context
from saas.production.aliyun_model_lease import HostModelLeaseAuthority
from saas.production.aliyun_sandbox import AliyunSandboxLauncher
from tests.saas.test_aliyun_sandbox import cloud as cloud


@pytest.fixture
def host_launch(cloud):
    leases = HostModelLeaseAuthority(b"l" * 32)
    launcher = AliyunSandboxLauncher(
        template="host-template",
        credential_file=cloud.key,
        scope=cloud.scope,
        model_leases=leases,
        model_gateway_url="https://control.invalid/platform-model/v1",
    )
    launcher.run = Mock(
        side_effect=lambda _id, command, **_kwargs: RemoteCommandResult(
            0, "/home/user" if "$HOME" in command else "", ""
        )
    )
    launcher.run_background = Mock()
    launcher.materialize_workspace = Mock(
        side_effect=lambda _id, **kw: f"{kw['workspace']}/{kw['repo_name']}"
    )
    return SimpleNamespace(
        cloud=cloud,
        launcher=launcher,
        leases=leases,
        host_id=uuid4().hex,
        token="h" * 43,
    )


def _start(case, **extra):
    return case.launcher.start_host(
        "sbx-test-1234",
        token=case.token,
        host_id=case.host_id,
        host_name="managed-test",
        server_url="https://control.invalid",
        **extra,
    )


def test_cloud_launch_stages_only_its_host_token_and_bound_lease_without_command_secrets(
    host_launch,
):
    c = host_launch
    with bind_runtime_context(c.cloud.runtime):
        assert _start(c, host_config={"providers": {}}) == "/home/user/workspace"
    writes = c.cloud.handle.files.write.call_args_list
    assert len(writes) == 2
    token_path, token = writes[0].args
    lease_path, lease = writes[1].args
    assert token_path.endswith("/host-token") and lease_path.endswith("/model-lease")
    assert token == c.token
    admitted = c.leases.verify(lease, host_id=c.host_id, launch_token=c.token)
    assert admitted.runtime == c.cloud.runtime
    assert admitted.expires_at - admitted.issued_at == c.launcher.token_ttl_s == 5400
    command = c.launcher.run_background.call_args.args[1]
    assert "/opt/venv/bin/python -I -m saas.production.aliyun_host" in command
    assert "OMNIGENT_HOST_TOKEN_FILE=" in command and "OMNIGENT_HOST_TOKEN=" not in command
    assert c.token not in command and lease not in command
    all_commands = "\n".join(call.args[1] for call in c.launcher.run.call_args_list)
    assert c.token not in all_commands and lease not in all_commands
    assert "e2b_" not in all_commands and "e2b_" not in str(writes)


def test_repositories_use_canonical_clone_options_and_collision_free_directories(host_launch):
    c = host_launch
    repos = [
        RepoWorkspace("https://github.com/one/api.git", "main", "api", GitCloneOptions(depth=1)),
        RepoWorkspace("https://github.com/two/api.git", None, "api"),
    ]
    stages = []
    with bind_runtime_context(c.cloud.runtime):
        assert _start(c, repos=repos, on_stage=stages.append) == "/home/user/workspace"
    calls = c.launcher.materialize_workspace.call_args_list
    assert len({call.kwargs["repo_name"] for call in calls}) == 2
    assert calls[0].kwargs["git_clone"].depth == 1
    assert stages == ["cloning", "starting"]
    assert c.launcher.capabilities.multi_repo and c.launcher.capabilities.git_clone_options


def test_single_checkout_is_the_returned_workspace(host_launch):
    c = host_launch
    with bind_runtime_context(c.cloud.runtime):
        result = _start(c, repos=[RepoWorkspace("https://github.com/one/api.git", None, "api")])
    assert result == "/home/user/workspace/api"


def test_start_requires_authorized_runtime_even_when_transport_scope_is_retained(host_launch):
    c = host_launch
    with pytest.raises(RuntimeError, match="runtime context is not bound"):
        _start(c)
    c.launcher.run.assert_not_called()
    c.cloud.handle.files.write.assert_not_called()


def test_context_switch_cannot_issue_or_deliver_a_cloud_host_lease(host_launch):
    c = host_launch
    with bind_runtime_context(replace(c.cloud.runtime, tenant_id=uuid4())):
        with pytest.raises(ValueError, match="identity"):
            _start(c)
    c.launcher.run.assert_not_called()
    c.cloud.handle.files.write.assert_not_called()


def test_transport_only_launcher_cannot_start_a_plain_unauthenticated_model_host(host_launch):
    c = host_launch
    c.launcher = c.cloud.launcher
    with bind_runtime_context(c.cloud.runtime):
        with pytest.raises(ValueError, match="authority"):
            _start(c)
    c.cloud.sdk.connect.assert_not_called()


def test_credential_delivery_failure_is_sanitized_and_private_files_are_removed(host_launch):
    c = host_launch
    c.cloud.handle.files.write.side_effect = RuntimeError("e2b_management_canary " + c.token)
    with bind_runtime_context(c.cloud.runtime):
        with pytest.raises(click.ClickException) as failure:
            _start(c)
    assert "e2b_management_canary" not in str(failure.value) and c.token not in str(failure.value)
    assert failure.value.__suppress_context__
    c.launcher.run_background.assert_not_called()
    assert c.launcher.run.call_args.args[1].startswith("rm -rf -- /home/user/.omnigent/runtime/")


def test_remote_sdk_command_failure_does_not_echo_management_credentials(cloud):
    from e2b.exceptions import SandboxException

    cloud.handle.commands.run.side_effect = SandboxException("e2b_management_canary")
    with pytest.raises(click.ClickException) as failure:
        cloud.launcher.run("sbx-test-1234", "id")
    assert "e2b_management_canary" not in str(failure.value)
