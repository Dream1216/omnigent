from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from saas.compatibility.runtime_partition import bind_runtime_context
from saas.production.aliyun_storage import (
    INPUT_MOUNT,
    OSS_ENDPOINT,
    OUTPUT_MOUNT,
    AliyunOssStorageConfig,
    AliyunSessionVolumeManager,
    AliyunStorageError,
    AliyunVolumeControl,
)
from tests.saas.test_tenant_sandbox import _runtime


def _config(runtime):
    return AliyunOssStorageConfig(
        team_id=uuid4(),
        tenant_id=runtime.tenant_id,
        workspace_id=runtime.physical_workspace_id,
        bucket="omnigent-p4-test-bucket",
        role_arn="acs:ram::1000000000000000:role/omnigent-p4-test",
    )


def _volume(spec, **changes):
    return {
        "volumeID": str(uuid4()),
        "volumeName": spec.name,
        "teamID": str(spec.team_id),
        "storageClass": "OSS",
        "status": "AVAILABLE",
        "ossVolumeConfig": {
            "bucketName": spec.bucket,
            "bucketPath": spec.bucket_path,
            "endpoint": OSS_ENDPOINT,
            "readOnly": spec.read_only,
        },
        "mountConfig": {"role": spec.role_arn},
        **changes,
    }


class Control(AliyunVolumeControl):
    def __init__(self):
        self.volumes = {}
        self.creates = []
        self.reads = []

    def find(self, *, team_id, name):
        assert team_id
        return [deepcopy(self.volumes[name])] if name in self.volumes else []

    def create(self, spec):
        self.creates.append(spec)
        self.volumes[spec.name] = _volume(spec)
        return deepcopy(self.volumes[spec.name])

    def read(self, *, team_id, volume_id):
        self.reads.append(volume_id)
        return next(deepcopy(v) for v in self.volumes.values() if v["volumeID"] == volume_id)


def test_storage_namespace_and_names_are_stable_and_session_scoped():
    runtime = _runtime()
    config = _config(runtime)
    session = uuid4()
    first = config.session(runtime, session)
    assert first == config.session(runtime, session)
    assert first.mount_points == {
        INPUT_MOUNT: first.volumes[0].name,
        OUTPUT_MOUNT: first.volumes[1].name,
    }
    assert first.volumes[0].read_only is True
    assert first.volumes[1].read_only is False
    assert all(f"/sessions/{session}/" in v.bucket_path for v in first.volumes)
    assert all(
        f"/tenants/{runtime.tenant_id}/spaces/{runtime.space_id}/" in v.bucket_path
        for v in first.volumes
    )
    other = config.session(runtime, uuid4())
    assert set(first.mount_points.values()).isdisjoint(other.mount_points.values())
    moved = config.session(replace(runtime, space_id=uuid4()), session)
    assert set(first.mount_points.values()).isdisjoint(moved.mount_points.values())
    changed_role = replace(config, role_arn=config.role_arn + "-rotated").session(runtime, session)
    assert set(first.mount_points.values()).isdisjoint(changed_role.mount_points.values())
    assert first.metadata["fc.sandbox.auth.role"] == config.role_arn
    assert first.metadata["omnigent-storage-session"] == str(session)


def test_project_namespaces_separate_unbound_and_moved_sessions_without_changing_v2_names():
    runtime = _runtime()
    config, session_id = _config(runtime), uuid4()
    legacy = config.session(runtime, session_id)
    first_project, second_project = uuid4(), uuid4()
    assert legacy == config.session(replace(runtime, project_id=first_project), session_id)
    current = replace(config, project_scoped=True)
    plans = [
        current.session(replace(runtime, project_id=project), session_id)
        for project in (None, first_project, second_project)
    ]
    names = set(legacy.mount_points.values())
    for project, plan in zip((None, first_project, second_project), plans, strict=True):
        assert names.isdisjoint(plan.mount_points.values())
        names.update(plan.mount_points.values())
        for spec in plan.volumes:
            assert spec.project_scoped and spec.project_id == project
            assert spec.space_id == runtime.space_id
            assert f"/projects/{project or 'unbound'}/sessions/{session_id}/" in spec.bucket_path
            assert spec.verify(_volume(spec))
    assert all(not spec.project_scoped and spec.project_id is None for spec in legacy.volumes)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("team_id", UUID(int=0)),
        ("workspace_id", True),
        ("workspace_id", 0),
        ("bucket", "bucket/*"),
        ("bucket", "UpperCase"),
        ("role_arn", "acs:ram::*:role/admin"),
        ("role_arn", "acs:ram::1000000000000000:role/admin/../other"),
        ("prefix", "/"),
        ("prefix", "a/../b"),
        ("prefix", "a/.hidden"),
        ("prefix", "a//b"),
    ],
)
def test_storage_configuration_rejects_broad_or_noncanonical_values(field, value):
    with pytest.raises(AliyunStorageError):
        replace(_config(_runtime()), **{field: value})


def test_storage_config_cannot_select_another_tenant_or_workspace():
    runtime = _runtime()
    config = _config(runtime)
    for other in (replace(runtime, tenant_id=uuid4()), replace(runtime, physical_workspace_id=92)):
        with pytest.raises(AliyunStorageError):
            config.session(other, uuid4())


def test_rebuild_reuses_two_verified_volumes_without_recreating_or_deleting_data():
    runtime = _runtime()
    config, control, session = _config(runtime), Control(), uuid4()
    manager = AliyunSessionVolumeManager(config, control, authorize=lambda _: runtime)
    with bind_runtime_context(runtime):
        first = manager.ensure(session)
        assert manager.ensure(session) == first
        assert len(control.creates) == 2
        assert len(control.volumes) == 2
    assert not hasattr(manager, "delete")


@pytest.mark.parametrize(
    "part", ["team", "role", "path", "readonly", "endpoint", "class", "error"]
)
def test_existing_cloud_metadata_must_match_the_exact_admitted_plan(part):
    runtime = _runtime()
    config, control, session = _config(runtime), Control(), uuid4()
    spec = config.session(runtime, session).volumes[0]
    volume = _volume(spec)
    if part == "team":
        volume["teamID"] = str(uuid4())
    elif part == "role":
        volume["mountConfig"]["role"] += "-broad"
    elif part == "path":
        volume["ossVolumeConfig"]["bucketPath"] = "/"
    elif part == "readonly":
        volume["ossVolumeConfig"]["readOnly"] = False
    elif part == "endpoint":
        volume["ossVolumeConfig"]["endpoint"] = "https://untrusted.example"
    elif part == "class":
        volume["storageClass"] = "AGENTIC_FS"
    else:
        volume["status"] = "ERROR"
        volume["statusReason"] = "private diagnostic"
    control.volumes[spec.name] = volume
    manager = AliyunSessionVolumeManager(config, control, authorize=lambda _: runtime)
    with bind_runtime_context(runtime), pytest.raises(AliyunStorageError) as raised:
        manager.ensure(session)
    assert control.creates == []
    assert "private diagnostic" not in str(raised.value)


def test_ambiguous_create_uses_name_readback_and_never_replays_the_mutation():
    runtime = _runtime()
    config, control, session = _config(runtime), Control(), uuid4()
    create = control.create

    def ambiguous(spec):
        create(spec)
        raise TimeoutError("signed request with private values")

    control.create = ambiguous
    with bind_runtime_context(runtime):
        AliyunSessionVolumeManager(config, control, authorize=lambda _: runtime).ensure(session)
    assert len(control.creates) == 2


def test_unconfirmed_create_fails_without_replay_or_caller_secret():
    runtime = _runtime()
    config, control, calls = _config(runtime), Control(), []

    def ambiguous(spec):
        calls.append(spec)
        raise TimeoutError("private values")

    control.create = ambiguous
    with bind_runtime_context(runtime), pytest.raises(AliyunStorageError) as raised:
        AliyunSessionVolumeManager(config, control, authorize=lambda _: runtime).ensure(uuid4())
    assert len(calls) == 1
    assert "private values" not in str(raised.value)


def test_current_context_and_fresh_authorization_are_required_before_cloud_mutation():
    runtime = _runtime()
    config, control = _config(runtime), Control()
    manager = AliyunSessionVolumeManager(
        config, control, authorize=lambda _: replace(runtime, tenant_id=uuid4())
    )
    with bind_runtime_context(runtime), pytest.raises(AliyunStorageError):
        manager.ensure(uuid4())
    assert control.creates == []


def test_revocation_between_volume_creates_stops_second_mutation():
    runtime = _runtime()
    config, control = _config(runtime), Control()
    revoked = [False]
    create = control.create

    def revoke_after_first(spec):
        result = create(spec)
        revoked[0] = True
        return result

    control.create = revoke_after_first
    manager = AliyunSessionVolumeManager(
        config,
        control,
        authorize=lambda _: replace(runtime, user_security_version=99) if revoked[0] else runtime,
    )
    with bind_runtime_context(runtime), pytest.raises(AliyunStorageError):
        manager.ensure(uuid4())
    assert len(control.creates) == 1


def test_creating_volumes_have_bounded_readiness_polling():
    runtime = _runtime()
    config, control, sleeps = _config(runtime), Control(), []
    create = control.create

    def creating(spec):
        create(spec)
        control.volumes[spec.name]["status"] = "CREATING"
        return control.volumes[spec.name]

    control.create = creating
    manager = AliyunSessionVolumeManager(
        config, control, authorize=lambda _: runtime, wait=sleeps.append
    )
    with bind_runtime_context(runtime), pytest.raises(AliyunStorageError, match="not ready"):
        manager.ensure(uuid4())
    assert len(control.creates) == 1
    assert len(control.reads) == len(sleeps) == 3


def test_revocation_during_readiness_wait_stops_cloud_polling():
    runtime = _runtime()
    config, control = _config(runtime), Control()
    revoked = [False]
    create = control.create

    def creating(spec):
        volume = create(spec)
        volume["status"] = "CREATING"
        return volume

    def revoke(_):
        revoked[0] = True

    control.create = creating
    manager = AliyunSessionVolumeManager(
        config,
        control,
        authorize=lambda _: replace(runtime, user_security_version=99) if revoked[0] else runtime,
        wait=revoke,
    )
    with bind_runtime_context(runtime), pytest.raises(AliyunStorageError, match="changed"):
        manager.ensure(uuid4())
    assert len(control.creates) == 1
    assert control.reads == []


def test_revocation_after_ambiguous_create_stops_readback_and_second_volume():
    runtime = _runtime()
    config, control, lookups = _config(runtime), Control(), []
    revoked = [False]
    create, find = control.create, control.find

    def lookup(**kwargs):
        lookups.append(kwargs["name"])
        return find(**kwargs)

    def ambiguous(spec):
        create(spec)
        revoked[0] = True
        raise TimeoutError("private request diagnostics")

    control.create, control.find = ambiguous, lookup
    manager = AliyunSessionVolumeManager(
        config,
        control,
        authorize=lambda _: replace(runtime, user_security_version=99) if revoked[0] else runtime,
    )
    with bind_runtime_context(runtime), pytest.raises(AliyunStorageError, match="changed"):
        manager.ensure(uuid4())
    assert len(control.creates) == len(lookups) == 1


def test_session_role_policy_limits_listing_and_writes_to_exact_prefixes():
    runtime = _runtime()
    session = _config(runtime).session(runtime, uuid4())
    statements = session.ram_policy["Statement"]
    listing, inputs, outputs = statements
    assert listing["Condition"]["StringLike"]["oss:Prefix"] == [
        v.bucket_path.lstrip("/") + "*" for v in session.volumes
    ]
    assert inputs["Action"] == ["oss:GetObject"]
    assert "oss:PutObject" in outputs["Action"]
    assert all("oss:PutBucket" not in statement["Action"] for statement in statements)
    assert inputs["Resource"] == [
        f"acs:oss:*:*:{session.volumes[0].bucket}{session.volumes[0].bucket_path}*"
    ]
    assert outputs["Resource"] == [
        f"acs:oss:*:*:{session.volumes[1].bucket}{session.volumes[1].bucket_path}*"
    ]


@pytest.mark.parametrize(
    "changes",
    [{"bucket_path": "/"}, {"read_only": False}, {"mount_path": "/opt/credentials"}],
)
def test_volume_specs_cannot_be_forged_to_select_broad_paths(changes):
    runtime = _runtime()
    spec = _config(runtime).session(runtime, uuid4()).volumes[0]
    with pytest.raises(AliyunStorageError):
        replace(spec, **changes)
