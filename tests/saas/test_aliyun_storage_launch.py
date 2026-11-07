from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from omnigent.onboarding.sandboxes.types import RepoWorkspace
from saas.compatibility.runtime_partition import bind_runtime_context
from saas.production.aliyun_sandbox import AliyunSandboxLauncher
from saas.production.aliyun_storage import AliyunOssStorageConfig, AliyunStorageError
from saas.production.aliyun_workspace_recovery import AliyunWorkspaceRecovery
from tests.saas.test_aliyun_host_launcher import _start
from tests.saas.test_aliyun_host_launcher import host_launch as host_launch
from tests.saas.test_aliyun_sandbox import cloud as cloud


def _storage(runtime, *, project_scoped=False):
    config = AliyunOssStorageConfig(
        uuid4(),
        runtime.tenant_id,
        runtime.physical_workspace_id,
        "omnigent-storage-test",
        "acs:ram::1000000000000000:role/omnigent-storage-test",
        project_scoped=project_scoped,
    )
    plan = config.session(runtime, uuid4())
    storage = Mock()
    storage.admit.return_value = storage.ensure.return_value = plan
    return storage, plan


@pytest.mark.parametrize("failure", [False, True])
def test_pinned_session_import_is_before_secrets_and_never_recloned(
    host_launch, tmp_path, failure
):
    c = host_launch
    storage, plan = _storage(c.cloud.runtime, project_scoped=True)
    c.cloud.info.metadata.update(plan.metadata)
    c.launcher._storage = storage
    raw = json.dumps(
        {
            "schema_version": 1,
            "tenant_id": str(c.cloud.runtime.tenant_id),
            "space_id": str(c.cloud.runtime.space_id),
            "project_id": str(c.cloud.runtime.project_id) if c.cloud.runtime.project_id else None,
            "workspace_id": c.cloud.runtime.physical_workspace_id,
            "session_id": str(plan.session_id),
            "host_id": c.host_id,
            "source_sandbox_id": "sbx-old",
            "archive_relative_path": "recovery/full.pax",
            "archive_sha256": "a" * 64,
            "tree_sha256": "b" * 64,
        }
    ).encode()
    descriptor = tmp_path / "restore.json"
    descriptor.write_bytes(raw)
    descriptor.chmod(0o400)
    c.launcher._workspace_recovery = AliyunWorkspaceRecovery(
        descriptor, hashlib.sha256(raw).hexdigest()
    )

    def import_before_bootstrap(*args, **kwargs):
        c.cloud.handle.files.write.assert_not_called()
        c.launcher.run_background.assert_not_called()
        c.launcher.materialize_workspace.assert_not_called()
        assert kwargs["plan"]["session_id"] == str(plan.session_id)
        assert kwargs["plan"]["repositories"] == ["repos/project"]
        if failure:
            raise ValueError("incomplete or corrupted backup")

    c.launcher._restore_workspace = Mock(side_effect=import_before_bootstrap)
    with bind_runtime_context(c.cloud.runtime):
        if failure:
            with pytest.raises(ValueError, match="backup"):
                _start(
                    c, repos=[RepoWorkspace("https://github.com/org/project.git", None, "project")]
                )
            c.cloud.handle.files.write.assert_not_called()
            c.launcher.run_background.assert_not_called()
        else:
            assert (
                _start(
                    c, repos=[RepoWorkspace("https://github.com/org/project.git", None, "project")]
                )
                == "/home/user/workspace"
            )
            c.launcher.run_background.assert_called_once()
    c.launcher.materialize_workspace.assert_not_called()
    c.launcher._restore_workspace.assert_called_once()


def test_provider_passes_exact_mounts_and_session_identity_to_qualified_sdk(cloud):
    storage, plan = _storage(cloud.runtime)
    launcher = AliyunSandboxLauncher(
        template="host-template", credential_file=cloud.key, scope=cloud.scope, storage=storage
    )
    with bind_runtime_context(cloud.runtime):
        assert launcher.provision("managed-storage") == cloud.handle.sandbox_id
    values = cloud.sdk.create.call_args.kwargs
    assert values["volume_mounts"] == plan.mount_points
    assert all(values["metadata"][key] == value for key, value in plan.metadata.items())
    assert set(values["envs"]) == {
        "OMNIGENT_HOST_WORKSPACE_ID",
        "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID",
    }
    storage.ensure.assert_called_once_with()


def test_denied_storage_admission_creates_no_microvm(cloud):
    storage, _ = _storage(cloud.runtime)
    storage.ensure.side_effect = AliyunStorageError("session denied")
    launcher = AliyunSandboxLauncher(
        template="host-template", credential_file=cloud.key, scope=cloud.scope, storage=storage
    )
    with bind_runtime_context(cloud.runtime), pytest.raises(AliyunStorageError):
        launcher.provision("managed-storage")
    cloud.sdk.create.assert_not_called()


def test_provider_independently_rejects_a_foreign_space_mount_plan(cloud):
    storage, _ = _storage(replace(cloud.runtime, space_id=uuid4()))
    launcher = AliyunSandboxLauncher(
        template="host-template", credential_file=cloud.key, scope=cloud.scope, storage=storage
    )
    with bind_runtime_context(cloud.runtime), pytest.raises(ValueError, match="scope"):
        launcher.provision("managed-wrong-space")
    cloud.sdk.create.assert_not_called()


@pytest.mark.parametrize(
    "field", ["omnigent-storage-session", "omnigent-storage-bindings", "fc.sandbox.auth.role"]
)
def test_reattach_rejects_mount_metadata_drift_without_creating_volumes_or_running_commands(
    cloud, field
):
    storage, plan = _storage(cloud.runtime)
    cloud.info.metadata.update(plan.metadata)
    cloud.info.metadata[field] += "-changed"
    launcher = AliyunSandboxLauncher(
        template="host-template", credential_file=cloud.key, scope=cloud.scope, storage=storage
    )
    with bind_runtime_context(cloud.runtime), pytest.raises(ValueError, match="metadata"):
        launcher.run(cloud.info.sandbox_id, "read-private-output")
    storage.ensure.assert_not_called()
    cloud.attach.assert_not_called()
    cloud.handle.commands.run.assert_not_called()


def test_same_tenant_different_session_cannot_execute_in_an_existing_storage_vm(cloud):
    storage, plan = _storage(cloud.runtime)
    _, other_plan = _storage(cloud.runtime)
    cloud.info.metadata.update(plan.metadata)
    storage.admit.return_value = other_plan
    launcher = AliyunSandboxLauncher(
        template="host-template", credential_file=cloud.key, scope=cloud.scope, storage=storage
    )
    with bind_runtime_context(cloud.runtime), pytest.raises(ValueError, match="metadata"):
        launcher.run(cloud.info.sandbox_id, "read-other-session-output")
    cloud.handle.commands.run.assert_not_called()
    storage.ensure.assert_not_called()


def test_disabling_storage_does_not_admit_an_old_storage_vm_for_execution(cloud):
    _, plan = _storage(cloud.runtime)
    cloud.info.metadata.update(plan.metadata)
    with bind_runtime_context(cloud.runtime), pytest.raises(ValueError, match="authority"):
        cloud.launcher.run(cloud.info.sandbox_id, "read-private-output")
    cloud.handle.commands.run.assert_not_called()


def test_revocation_does_not_prevent_persisted_scope_cleanup(cloud):
    storage, plan = _storage(cloud.runtime)
    cloud.info.metadata.update(plan.metadata)
    storage.admit.side_effect = AliyunStorageError("permission revoked")
    launcher = AliyunSandboxLauncher(
        template="host-template", credential_file=cloud.key, scope=cloud.scope, storage=storage
    )
    launcher.terminate(cloud.info.sandbox_id)
    cloud.sdk.kill.assert_called_once()
    storage.admit.assert_not_called()
    storage.ensure.assert_not_called()


def test_storage_workspace_keeps_mounts_visible_and_repositories_local(host_launch):
    c = host_launch
    storage, plan = _storage(c.cloud.runtime)
    c.launcher._storage = storage
    c.cloud.info.metadata.update(plan.metadata)
    repo = RepoWorkspace("https://github.com/example/inputs.git", None, "inputs")
    with bind_runtime_context(c.cloud.runtime):
        workspace = _start(c, repos=[repo])
    assert workspace == "/home/user/workspace"
    checkout = c.launcher.materialize_workspace.call_args.kwargs
    assert checkout["workspace"] == "/home/user/workspace/repos"
    assert checkout["repo_name"] == "inputs"
    storage.ensure.assert_not_called()


def test_storage_revocation_before_host_launch_delivers_no_host_credentials(host_launch):
    c = host_launch
    storage, plan = _storage(c.cloud.runtime)
    c.launcher._storage = storage
    c.cloud.info.metadata.update(plan.metadata)
    storage.admit.side_effect = AliyunStorageError("permission revoked")
    with bind_runtime_context(c.cloud.runtime), pytest.raises(AliyunStorageError):
        _start(c)
    c.cloud.handle.files.write.assert_not_called()
    c.launcher.run_background.assert_not_called()
