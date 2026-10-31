from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from omnigent.db.db_models import workspace_scope
from omnigent.db.utils import make_named_managed_session_maker
from omnigent.debug_logging import runner_log_scope
from omnigent.server.auth import LEVEL_OWNER
from saas.compatibility.runtime_partition import bind_runtime_context
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import (
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.resolver import SqlAlchemyContextResolver
from saas.production.aliyun_storage import AliyunOssStorageConfig, AliyunStorageError
from saas.production.aliyun_storage_admission import (
    AliyunCurrentSessionStorage,
    AliyunStorageSessionAuthorizer,
)
from tests.saas.test_aliyun_model_broker import broker_case as broker_case
from tests.saas.test_aliyun_storage import Control
from tests.saas.test_control_plane_resolver import COMPATIBILITY_POLICY
from tests.saas.test_control_plane_resolver import control_plane as control_plane


@pytest.fixture
def storage_case(broker_case):
    c = broker_case
    c.control = Control()
    c.storage_config = AliyunOssStorageConfig(
        uuid4(),
        c.runtime.tenant_id,
        c.runtime.physical_workspace_id,
        "omnigent-storage-test",
        "acs:ram::1000000000000000:role/omnigent-storage-test",
    )
    c.authorize = AliyunStorageSessionAuthorizer(
        sessions=make_named_managed_session_maker(
            c.factory.kw["bind"], query_name_prefix="test.aliyun_storage"
        ),
        resolver=SqlAlchemyContextResolver(
            c.factory,
            COMPATIBILITY_POLICY,
            project_authorizer=ProjectAuthorizer(c.factory),
        ),
        conversations=c.conversations,
        permissions=c.permissions,
    )
    c.storage = AliyunCurrentSessionStorage((c.storage_config,), c.control, authorize=c.authorize)
    return c


def _binding(c, **changes):
    row = RuntimeResourceBindingRecord(
        id=uuid4(),
        runtime_partition_id=c.runtime.runtime_partition_id,
        tenant_id=c.runtime.tenant_id,
        space_id=c.runtime.space_id,
        project_id=None,
        resource_type="session",
        runtime_resource_id=c.session_id.hex,
        saas_resource_id=uuid4(),
        partition_generation=c.runtime.placement_generation,
        binding_generation=1,
        status="active",
    )
    for key, value in changes.items():
        setattr(row, key, value)
    with c.factory.begin() as db:
        db.add(row)
    return row.id


def _project(c):
    project = uuid4()
    with c.factory.begin() as db:
        db.add(
            ProjectRecord(
                id=project,
                tenant_id=c.runtime.tenant_id,
                space_id=c.runtime.space_id,
                name="Storage admission",
                visibility="restricted",
                created_by=c.runtime.actor_id,
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=c.runtime.tenant_id,
                space_id=c.runtime.space_id,
                project_id=project,
                subject_type="user",
                subject_id=c.runtime.actor_id,
                role="edit",
                status="active",
                created_by=c.runtime.actor_id,
                version=1,
            )
        )
    return project


@pytest.mark.parametrize("form", ["hex", "hyphen"])
def test_real_owner_and_log_hint_resolve_session_without_cloud_side_effects(storage_case, form):
    c = storage_case
    hint = c.session_id.hex if form == "hex" else str(c.session_id)
    with bind_runtime_context(c.runtime), runner_log_scope(hint, None):
        plan = c.storage.admit()
        assert plan.session_id == c.session_id
        assert c.control.creates == []
        assert c.storage.ensure() == plan
    assert len(c.control.creates) == 2


@pytest.mark.parametrize("hint", [None, "", "not-a-session", str(UUID(int=0)), " " + "a" * 32])
def test_missing_or_noncanonical_logging_hint_cannot_select_storage(storage_case, hint):
    c = storage_case
    with (
        bind_runtime_context(c.runtime),
        runner_log_scope(hint, None),
        pytest.raises(AliyunStorageError),
    ):
        c.storage.ensure()
    assert c.control.creates == []


@pytest.mark.parametrize("scenario", ["missing", "other_owner", "revoked", "stale_user"])
def test_logging_context_never_substitutes_for_session_authority(storage_case, scenario):
    c = storage_case
    session = c.session_id
    with bind_runtime_context(c.runtime):
        if scenario == "missing":
            session = uuid4()
        elif scenario == "other_owner":
            other = c.conversations.create_conversation(conversation_id=uuid4().hex)
            c.permissions.ensure_user("another-storage-owner")
            c.permissions.grant("another-storage-owner", other.id, LEVEL_OWNER)
            session = UUID(other.id)
        elif scenario == "revoked":
            c.permissions.revoke(c.runtime.runtime_user_key, c.session_id.hex)
        else:
            with c.factory.begin() as db:
                db.get(GlobalUser, c.runtime.actor_id).security_version += 1
        with runner_log_scope(session.hex, None), pytest.raises(AliyunStorageError):
            c.storage.ensure()
    assert c.control.creates == []


@pytest.mark.parametrize(
    "changes", [{"status": "retired"}, {"status": "suspended"}, {"partition_generation": 9}]
)
def test_inactive_or_stale_binding_cannot_fall_back_to_native_owner(storage_case, changes):
    c = storage_case
    _binding(c, **changes)
    with (
        bind_runtime_context(c.runtime),
        runner_log_scope(c.session_id.hex, None),
        pytest.raises(AliyunStorageError),
    ):
        c.storage.ensure()
    assert c.control.creates == []


def test_duplicate_session_and_conversation_bindings_are_rejected(storage_case):
    c = storage_case
    _binding(c)
    _binding(c, resource_type="conversation", runtime_resource_id=str(c.session_id))
    with bind_runtime_context(c.runtime), pytest.raises(AliyunStorageError, match="ambiguous"):
        c.authorize(c.session_id)


def test_uppercase_uuid_binding_cannot_bypass_project_scope(storage_case):
    c = storage_case
    project = _project(c)
    _binding(c, project_id=project, runtime_resource_id=str(c.session_id).upper())
    with bind_runtime_context(c.runtime), pytest.raises(AliyunStorageError):
        c.authorize(c.session_id)


@pytest.mark.parametrize("revocation", ["role", "status"])
def test_project_session_requires_matching_project_context_and_fresh_run_permission(
    storage_case, revocation
):
    c = storage_case
    project = _project(c)
    _binding(c, project_id=project)
    with bind_runtime_context(c.runtime), pytest.raises(AliyunStorageError):
        c.authorize(c.session_id)
    project_runtime = replace(c.runtime, project_id=project)
    with bind_runtime_context(project_runtime):
        assert c.authorize(c.session_id) == project_runtime
        with c.factory.begin() as db:
            membership = db.query(ProjectMembershipRecord).filter_by(project_id=project).one()
            if revocation == "role":
                membership.role = "read"
            else:
                membership.status = "revoked"
            membership.version += 1
        with pytest.raises(AliyunStorageError):
            c.authorize(c.session_id)
    assert c.control.creates == []


def test_native_project_mapping_cannot_bypass_project_admission_without_session_binding(
    storage_case,
):
    c = storage_case
    logical = _project(c)
    native = uuid4()
    _binding(
        c,
        resource_type="project",
        runtime_resource_id=native.hex,
        saas_resource_id=logical,
        project_id=logical,
    )
    with bind_runtime_context(c.runtime):
        c.conversations.set_conversation_project(c.session_id.hex, native.hex)
        with pytest.raises(AliyunStorageError):
            c.authorize(c.session_id)
    with bind_runtime_context(replace(c.runtime, project_id=logical)):
        assert c.authorize(c.session_id).project_id == logical


def test_database_workspace_mismatch_is_denied_before_cloud_access(storage_case):
    c = storage_case
    with bind_runtime_context(c.runtime), workspace_scope(92), pytest.raises(AliyunStorageError):
        c.authorize(c.session_id)
    assert c.control.creates == []
