from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane import (
    PERMISSION_CATALOG,
    AuthorizationDecisionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    LifecycleError,
    MembershipGovernanceService,
    ProjectAdministrationService,
    ProjectAuthorizationError,
    ProjectAuthorizer,
    ProjectMembershipRecord,
    ProjectRecord,
    ProjectRemovalImpactProvider,
    ProvisioningTarget,
    ResourceGrantRecord,
    RuntimeBindingSagaRecord,
    RuntimeBindingSagaService,
    RuntimeBindingService,
    RuntimeCompatibilityPolicy,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
    SaasBase,
    Space,
    SpaceMembership,
    SqlAlchemyContextResolver,
    Tenant,
    TenantMembership,
    permission_catalog_payload,
)
from saas.control_plane.idempotency import scoped_idempotency_key


@dataclass(frozen=True, slots=True)
class ProjectScope:
    tenant_id: UUID
    space_id: UUID
    owner_id: UUID
    admin_id: UUID
    manager_id: UUID
    member_id: UUID


def _binding_policy(*source_revisions: str) -> RuntimeCompatibilityPolicy:
    return RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
        allowed_source_revisions=frozenset(source_revisions),
        allowed_schema_revisions=frozenset({"c4d5e6f7a8b9"}),
        adapter_contract_version="0.2.0",
    )


class _IdempotentProvisioner:
    def __init__(self) -> None:
        self.resources: dict[str, str] = {}
        self.provision_calls: list[str] = []
        self.compensation_calls: list[str] = []
        self.fail_compensation = False

    def provision(
        self,
        *,
        target: ProvisioningTarget,
        resource_type: str,
        saas_resource_id: UUID,
        idempotency_key: str,
    ) -> str:
        assert target.physical_partition_key != "0"
        self.provision_calls.append(idempotency_key)
        return self.resources.setdefault(idempotency_key, f"{resource_type}-{saas_resource_id}")

    def compensate(
        self,
        *,
        target: ProvisioningTarget,
        resource_type: str,
        runtime_resource_id: str,
        idempotency_key: str,
    ) -> None:
        del target, resource_type, runtime_resource_id
        self.compensation_calls.append(idempotency_key)
        if self.fail_compensation:
            from saas.control_plane import RuntimeProvisioningError

            raise RuntimeProvisioningError("compensation_failed", "injected compensation failure")


@pytest.fixture
def project_control_plane() -> Iterator[tuple[sessionmaker[Session], ProjectScope]]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    scope = ProjectScope(
        tenant_id=uuid4(),
        space_id=uuid4(),
        owner_id=uuid4(),
        admin_id=uuid4(),
        manager_id=uuid4(),
        member_id=uuid4(),
    )
    with factory.begin() as db:
        db.add_all(
            GlobalUser(id=user_id, status="active", security_version=1)
            for user_id in (
                scope.owner_id,
                scope.admin_id,
                scope.manager_id,
                scope.member_id,
            )
        )
        db.add(
            Tenant(
                id=scope.tenant_id,
                slug="project-auth",
                name="Project Auth",
                status="active",
                plan="team",
                home_region="cn-east-1",
            )
        )
        db.flush()
        db.add(
            Space(
                id=scope.space_id,
                tenant_id=scope.tenant_id,
                slug="engineering",
                name="Engineering",
                status="active",
            )
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=scope.tenant_id,
                    user_id=scope.owner_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=scope.tenant_id,
                    user_id=scope.admin_id,
                    role="admin",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=scope.tenant_id,
                    user_id=scope.manager_id,
                    role="member",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=scope.tenant_id,
                    user_id=scope.member_id,
                    role="member",
                    status="active",
                    version=1,
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                SpaceMembership(
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    user_id=scope.owner_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                SpaceMembership(
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    user_id=scope.admin_id,
                    role="admin",
                    status="active",
                    version=1,
                ),
                SpaceMembership(
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    user_id=scope.manager_id,
                    role="member",
                    status="active",
                    version=1,
                ),
                SpaceMembership(
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    user_id=scope.member_id,
                    role="member",
                    status="active",
                    version=1,
                ),
            ]
        )
    yield factory, scope
    engine.dispose()


def _context(scope: ProjectScope, actor_id: UUID, trace: str) -> RequestContext:
    return RequestContext(
        actor_id=actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        project_id=None,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id=trace,
    )


def _create_restricted_project(
    factory: sessionmaker[Session], scope: ProjectScope
) -> tuple[ProjectAdministrationService, ProjectAuthorizer, UUID]:
    authorizer = ProjectAuthorizer(factory)
    service = ProjectAdministrationService(factory, authorizer)
    created = service.create_project(
        _context(scope, scope.owner_id, "create-project"),
        name="Restricted project",
        visibility="restricted",
        idempotency_key="project-create",
    )
    return service, authorizer, created.project_id


def test_permission_catalog_is_versioned_complete_and_content_separated() -> None:
    payload = permission_catalog_payload()

    assert payload["policy_version"]
    permissions = payload["permissions"]
    assert isinstance(permissions, list)
    assert len(permissions) == len(PERMISSION_CATALOG)
    roles = payload["roles"]
    assert isinstance(roles, dict)
    tenant_roles = roles["tenant"]
    space_roles = roles["space"]
    resource_roles = roles["resource"]
    assert isinstance(tenant_roles, dict)
    assert isinstance(space_roles, dict)
    assert isinstance(resource_roles, dict)
    assert "project.content.read" not in tenant_roles["owner"]
    assert "project.content.read" not in tenant_roles["admin"]
    assert "project.content.read" not in space_roles["owner"]
    assert "project.content.read" not in space_roles["admin"]
    assert resource_roles["conversation"]["manage"] == []
    assert "project.update" not in resource_roles["conversation"]["owner"]


def test_project_creation_is_atomic_idempotent_and_creator_owned(project_control_plane) -> None:
    factory, scope = project_control_plane
    service = ProjectAdministrationService(factory)
    request = _context(scope, scope.owner_id, "create-idempotent")

    created = service.create_project(
        request,
        name="Private project",
        visibility="private",
        idempotency_key="create-private",
    )
    replayed = service.create_project(
        request,
        name="Private project",
        visibility="private",
        idempotency_key="create-private",
    )

    assert replayed.project_id == created.project_id
    assert replayed.replayed is True
    with factory() as db:
        membership = db.get(
            ProjectMembershipRecord,
            (created.project_id, "user", scope.owner_id),
        )
        assert membership is not None
        assert membership.role == "owner"
        assert membership.status == "active"


def test_tenant_and_space_admin_metadata_does_not_imply_content(project_control_plane) -> None:
    factory, scope = project_control_plane
    _service, authorizer, project_id = _create_restricted_project(factory, scope)
    admin = _context(scope, scope.admin_id, "admin-content-separation")

    metadata = authorizer.evaluate(admin, action="project.read_metadata", project_id=project_id)
    content = authorizer.evaluate(admin, action="project.content.read", project_id=project_id)

    assert metadata.allowed is True
    assert content.allowed is False
    assert content.reason == "permission_not_granted"
    with pytest.raises(ProjectAuthorizationError) as exc_info:
        authorizer.require(admin, action="project.content.read", project_id=project_id)
    assert exc_info.value.code == "permission_not_granted"


def test_space_visibility_and_explicit_project_membership_are_additive(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    service, authorizer, project_id = _create_restricted_project(factory, scope)
    member = _context(scope, scope.member_id, "member-access")

    assert not authorizer.evaluate(
        member, action="project.content.read", project_id=project_id
    ).allowed
    service.update_visibility(
        _context(scope, scope.owner_id, "visibility-space"),
        project_id=project_id,
        visibility="space",
        expected_authorization_version=1,
        idempotency_key="visibility-space",
    )
    assert authorizer.evaluate(
        member, action="project.content.read", project_id=project_id
    ).allowed
    service.set_project_membership(
        _context(scope, scope.owner_id, "grant-space-visible-operator"),
        project_id=project_id,
        subject_type="user",
        subject_id=scope.manager_id,
        role="operate",
        expires_at=None,
        idempotency_key="grant-space-visible-operator",
    )
    manager = _context(scope, scope.manager_id, "space-visible-operator")
    assert authorizer.evaluate(
        manager, action="project.content.read", project_id=project_id
    ).allowed
    assert authorizer.evaluate(manager, action="run.cancel", project_id=project_id).allowed
    service.update_visibility(
        _context(scope, scope.owner_id, "visibility-restricted"),
        project_id=project_id,
        visibility="restricted",
        expected_authorization_version=3,
        idempotency_key="visibility-restricted",
    )
    service.set_project_membership(
        _context(scope, scope.owner_id, "grant-reader"),
        project_id=project_id,
        subject_type="user",
        subject_id=scope.member_id,
        role="read",
        expires_at=None,
        idempotency_key="grant-reader",
    )
    assert authorizer.evaluate(
        member, action="project.content.read", project_id=project_id
    ).allowed


def test_manage_role_is_content_blind_and_cannot_over_delegate(project_control_plane) -> None:
    factory, scope = project_control_plane
    service, authorizer, project_id = _create_restricted_project(factory, scope)
    owner = _context(scope, scope.owner_id, "grant-manager")
    service.set_project_membership(
        owner,
        project_id=project_id,
        subject_type="user",
        subject_id=scope.manager_id,
        role="manage",
        expires_at=None,
        idempotency_key="grant-manager",
    )
    manager = _context(scope, scope.manager_id, "manager-delegation")

    assert authorizer.evaluate(manager, action="grant.manage", project_id=project_id).allowed
    assert not authorizer.evaluate(
        manager, action="project.content.read", project_id=project_id
    ).allowed
    with pytest.raises(LifecycleError) as exc_info:
        service.set_project_membership(
            manager,
            project_id=project_id,
            subject_type="user",
            subject_id=scope.member_id,
            role="read",
            expires_at=None,
            idempotency_key="manager-over-delegates",
        )
    assert exc_info.value.code == "delegation_scope_exceeded"


def test_resource_grant_is_exact_and_expired_grant_fails_closed(project_control_plane) -> None:
    factory, scope = project_control_plane
    service, authorizer, project_id = _create_restricted_project(factory, scope)
    resource_id = uuid4()
    other_resource_id = uuid4()
    owner = _context(scope, scope.owner_id, "resource-grant-owner")
    service.set_resource_grant(
        owner,
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
        subject_type="user",
        subject_id=scope.member_id,
        role="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        idempotency_key="resource-reader",
    )
    member = _context(scope, scope.member_id, "resource-reader")

    assert authorizer.evaluate(
        member,
        action="project.content.read",
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
    ).allowed
    service.set_resource_grant(
        owner,
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
        subject_type="user",
        subject_id=scope.member_id,
        role="owner",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        idempotency_key="resource-owner",
    )
    assert authorizer.evaluate(
        member,
        action="project.content.edit",
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
    ).allowed
    assert not authorizer.evaluate(
        member,
        action="project.update",
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
    ).allowed
    with pytest.raises(LifecycleError) as exc_info:
        service.set_resource_grant(
            owner,
            project_id=project_id,
            resource_type="conversation",
            resource_id=other_resource_id,
            subject_type="user",
            subject_id=scope.member_id,
            role="manage",
            expires_at=None,
            idempotency_key="resource-manage-no-effect",
        )
    assert exc_info.value.code == "resource_role_has_no_effect"
    assert not authorizer.evaluate(
        member,
        action="project.content.read",
        project_id=project_id,
        resource_type="conversation",
        resource_id=other_resource_id,
    ).allowed
    assert not authorizer.evaluate(
        member,
        action="project.content.read",
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
        now=datetime.now(timezone.utc) + timedelta(minutes=10),
    ).allowed


def test_resource_grant_revoke_is_atomic_idempotent_and_invalidates_access(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    service, authorizer, project_id = _create_restricted_project(factory, scope)
    resource_id = uuid4()
    owner = _context(scope, scope.owner_id, "resource-revoke-owner")
    member = _context(scope, scope.member_id, "resource-revoke-member")
    created = service.set_resource_grant(
        owner,
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
        subject_type="user",
        subject_id=scope.member_id,
        role="read",
        expires_at=None,
        idempotency_key="resource-revoke-create",
    )
    assert created.grant_id is not None
    assert authorizer.evaluate(
        member,
        action="project.content.read",
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
    ).allowed

    revoked = service.revoke_resource_grant(
        owner,
        project_id=project_id,
        grant_id=created.grant_id,
        idempotency_key="resource-revoke",
    )
    replay = service.revoke_resource_grant(
        owner,
        project_id=project_id,
        grant_id=created.grant_id,
        idempotency_key="resource-revoke",
    )

    assert revoked.status == "revoked"
    assert replay.replayed is True
    assert replay.authorization_version == revoked.authorization_version
    assert not authorizer.evaluate(
        member,
        action="project.content.read",
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
    ).allowed
    with factory() as db:
        grant = db.get(ResourceGrantRecord, created.grant_id)
        assert grant is not None and grant.status == "revoked"
        outbox = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key
                == scoped_idempotency_key("tenant", scope.tenant_id, "resource-revoke")
            )
        ).scalar_one()
        assert outbox.event_type == "resource.grant.revoked"


def test_stale_membership_snapshot_denies_and_decision_is_persisted(project_control_plane) -> None:
    factory, scope = project_control_plane
    _service, authorizer, project_id = _create_restricted_project(factory, scope)
    stale = _context(scope, scope.admin_id, "stale-project-snapshot")
    with factory.begin() as db:
        membership = db.get(
            SpaceMembership,
            (scope.tenant_id, scope.space_id, scope.admin_id),
        )
        assert membership is not None
        membership.version += 1

    decision = authorizer.evaluate(stale, action="project.read_metadata", project_id=project_id)

    assert decision.allowed is False
    assert decision.reason == "authorization_snapshot_stale"
    with factory() as db:
        record = db.get(AuthorizationDecisionRecord, decision.decision_id)
        assert record is not None
        assert record.allowed is False


def test_last_project_owner_and_cross_scope_binding_are_database_guarded(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    service, _authorizer, project_id = _create_restricted_project(factory, scope)
    owner = _context(scope, scope.owner_id, "owner-invariant")

    with pytest.raises(LifecycleError) as exc_info:
        service.revoke_project_membership(
            owner,
            project_id=project_id,
            subject_type="user",
            subject_id=scope.owner_id,
            idempotency_key="revoke-last-owner",
        )
    assert exc_info.value.code == "last_project_owner"

    other_tenant_id, other_space_id, other_project_id = uuid4(), uuid4(), uuid4()
    placement_id, partition_id = uuid4(), uuid4()
    with factory.begin() as db:
        db.add(
            Tenant(
                id=other_tenant_id,
                slug="binding-other",
                name="Binding Other",
                status="active",
                plan="team",
                home_region="cn-east-1",
            )
        )
        db.flush()
        db.add(
            Space(
                id=other_space_id,
                tenant_id=other_tenant_id,
                slug="other",
                name="Other",
                status="active",
            )
        )
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-a",
                object_store_ref="object-a",
                kms_key_ref="kms-a",
                official_schema_revision="schema-a",
                capacity_class="shared",
                status="active",
            )
        )
        db.flush()
        db.add(
            ProjectRecord(
                id=other_project_id,
                tenant_id=other_tenant_id,
                space_id=other_space_id,
                name="Other Project",
                visibility="restricted",
                created_by=scope.owner_id,
                status="active",
                authorization_version=1,
            )
        )
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key="71",
                placement_generation=1,
                source_revision="revision-a",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
    with pytest.raises(IntegrityError):
        with factory.begin() as db:
            db.add(
                RuntimeResourceBindingRecord(
                    id=uuid4(),
                    runtime_partition_id=partition_id,
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    project_id=other_project_id,
                    resource_type="conversation",
                    runtime_resource_id="cross-scope",
                    saas_resource_id=uuid4(),
                    partition_generation=1,
                    binding_generation=1,
                    status="active",
                )
            )


def test_authorized_project_context_routes_runtime_resource(project_control_plane) -> None:
    factory, scope = project_control_plane
    service, authorizer, project_id = _create_restricted_project(factory, scope)
    resource_id, placement_id, partition_id = uuid4(), uuid4(), uuid4()
    owner = _context(scope, scope.owner_id, "runtime-project")
    service.set_resource_grant(
        owner,
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
        subject_type="user",
        subject_id=scope.member_id,
        role="read",
        expires_at=None,
        idempotency_key="runtime-resource-reader",
    )
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-project",
                object_store_ref="object-project",
                kms_key_ref="kms-project",
                official_schema_revision="c4d5e6f7a8b9",
                capacity_class="shared",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key="73",
                placement_generation=2,
                source_revision="ab4bcaa7525ce45749271cb7d53403d2f240f523",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=partition_id,
                user_id=scope.member_id,
                runtime_user_key="member-runtime",
                status="active",
            )
        )
        db.add(
            RuntimeResourceBindingRecord(
                id=uuid4(),
                runtime_partition_id=partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                project_id=project_id,
                resource_type="conversation",
                runtime_resource_id="conversation-runtime",
                saas_resource_id=resource_id,
                partition_generation=2,
                binding_generation=1,
                status="active",
            )
        )
    member = _context(scope, scope.member_id, "runtime-project-member")
    project_context = authorizer.bind_project_context(
        member,
        action="project.content.read",
        project_id=project_id,
        resource_type="conversation",
        resource_id=resource_id,
    )
    resolver = SqlAlchemyContextResolver(
        factory,
        RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
            allowed_source_revisions=frozenset({"ab4bcaa7525ce45749271cb7d53403d2f240f523"}),
            allowed_schema_revisions=frozenset({"c4d5e6f7a8b9"}),
            adapter_contract_version="0.2.0",
        ),
        project_authorizer=authorizer,
    )

    runtime = resolver.resolve_existing_resource(
        project_context,
        resource_type="conversation",
        saas_resource_id=resource_id,
    )

    assert runtime.project_id == project_id
    assert runtime.physical_workspace_id == 73


def test_resource_grant_model_rejects_duplicate_active_grants(project_control_plane) -> None:
    factory, scope = project_control_plane
    _service, _authorizer, project_id = _create_restricted_project(factory, scope)
    common = {
        "tenant_id": scope.tenant_id,
        "space_id": scope.space_id,
        "project_id": project_id,
        "resource_type": "conversation",
        "resource_id": uuid4(),
        "subject_type": "user",
        "subject_id": scope.member_id,
        "role": "read",
        "status": "active",
        "created_by": scope.owner_id,
        "version": 1,
    }
    with pytest.raises(IntegrityError):
        with factory.begin() as db:
            db.add_all(
                [
                    ResourceGrantRecord(id=uuid4(), **common),
                    ResourceGrantRecord(id=uuid4(), **common),
                ]
            )


def test_binding_service_is_idempotent_and_rejects_duplicate_active_resource(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    _projects, authorizer, project_id = _create_restricted_project(factory, scope)
    partition_id, placement_id, resource_id = uuid4(), uuid4(), uuid4()
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="binding-db",
                object_store_ref="binding-object",
                kms_key_ref="binding-kms",
                official_schema_revision="c4d5e6f7a8b9",
                capacity_class="shared",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key="79",
                placement_generation=3,
                source_revision="revision-binding",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
    service = RuntimeBindingService(factory, authorizer, _binding_policy("revision-binding"))
    owner = _context(scope, scope.owner_id, "binding-owner")
    created = service.bind_resource(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        runtime_resource_id="runtime-conversation-1",
        saas_resource_id=resource_id,
        expected_partition_generation=3,
        idempotency_key="binding-create",
    )
    replay = service.bind_resource(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        runtime_resource_id="runtime-conversation-1",
        saas_resource_id=resource_id,
        expected_partition_generation=3,
        idempotency_key="binding-create",
    )

    assert replay.binding_id == created.binding_id
    assert replay.replayed is True
    with pytest.raises(LifecycleError) as exc_info:
        service.bind_resource(
            owner,
            project_id=project_id,
            runtime_partition_id=partition_id,
            resource_type="conversation",
            runtime_resource_id="runtime-conversation-2",
            saas_resource_id=resource_id,
            expected_partition_generation=3,
            idempotency_key="binding-duplicate-saas-resource",
        )
    assert exc_info.value.code == "active_binding_exists"

    with pytest.raises(LifecycleError) as exc_info:
        service.retire_binding(
            owner,
            binding_id=created.binding_id,
            expected_binding_generation=2,
            idempotency_key="binding-stale-retire",
        )
    assert exc_info.value.code == "binding_generation_stale"
    retired = service.retire_binding(
        owner,
        binding_id=created.binding_id,
        expected_binding_generation=1,
        idempotency_key="binding-retire",
    )
    assert retired.status == "retired"


def test_binding_transaction_rolls_back_when_outbox_persistence_fails(
    project_control_plane, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory, scope = project_control_plane
    _projects, authorizer, project_id = _create_restricted_project(factory, scope)
    partition_id, placement_id, resource_id = uuid4(), uuid4(), uuid4()
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="rollback-db",
                object_store_ref="rollback-object",
                kms_key_ref="rollback-kms",
                official_schema_revision="c4d5e6f7a8b9",
                capacity_class="shared",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key="83",
                placement_generation=1,
                source_revision="revision-rollback",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
    service = RuntimeBindingService(factory, authorizer, _binding_policy("revision-rollback"))

    def _fail_event(*_args, **_kwargs) -> None:
        raise RuntimeError("injected outbox failure")

    monkeypatch.setattr(service, "_event", _fail_event)
    with pytest.raises(RuntimeError, match="injected outbox failure"):
        service.bind_resource(
            _context(scope, scope.owner_id, "binding-rollback"),
            project_id=project_id,
            runtime_partition_id=partition_id,
            resource_type="conversation",
            runtime_resource_id="runtime-rollback",
            saas_resource_id=resource_id,
            expected_partition_generation=1,
            idempotency_key="binding-rollback",
        )
    with factory() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeResourceBindingRecord)
                .where(RuntimeResourceBindingRecord.saas_resource_id == resource_id)
            )
            == 0
        )


def test_member_removal_preflight_revokes_project_and_resource_access_atomically(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    projects, _authorizer, project_id = _create_restricted_project(factory, scope)
    owner = _context(scope, scope.owner_id, "removal-project-owner")
    projects.set_project_membership(
        owner,
        project_id=project_id,
        subject_type="user",
        subject_id=scope.member_id,
        role="read",
        expires_at=None,
        idempotency_key="removal-project-reader",
    )
    grant = projects.set_resource_grant(
        owner,
        project_id=project_id,
        resource_type="conversation",
        resource_id=uuid4(),
        subject_type="user",
        subject_id=scope.member_id,
        role="read",
        expires_at=None,
        idempotency_key="removal-resource-reader",
    )
    assert grant.grant_id is not None
    provider = ProjectRemovalImpactProvider(factory)
    governance = MembershipGovernanceService(factory, provider)
    now = datetime.now(timezone.utc)
    preflight = governance.create_removal_preflight(
        actor_id=scope.owner_id,
        tenant_id=scope.tenant_id,
        user_id=scope.member_id,
        idempotency_key="project-removal-preflight",
        now=now,
    )
    assert preflight.status == "ready"

    removed = governance.execute_member_removal(
        actor_id=scope.owner_id,
        tenant_id=scope.tenant_id,
        preflight_id=preflight.preflight_id,
        reason="member left the Project",
        reauthenticated_at=now,
        idempotency_key="project-removal-execute",
        now=now,
    )

    assert removed.revoked_project_memberships == 1
    assert removed.revoked_resource_grants == 1
    assert removed.changed_project_authorizations == 1
    with factory() as db:
        membership = db.get(
            ProjectMembershipRecord,
            (project_id, "user", scope.member_id),
        )
        resource_grant = db.get(ResourceGrantRecord, grant.grant_id)
        project = db.get(ProjectRecord, project_id)
        assert membership is not None and membership.status == "revoked"
        assert resource_grant is not None and resource_grant.status == "revoked"
        assert project is not None and project.authorization_version == 4


def test_member_removal_preflight_blocks_active_project_owner(project_control_plane) -> None:
    factory, scope = project_control_plane
    projects, _authorizer, project_id = _create_restricted_project(factory, scope)
    projects.set_project_membership(
        _context(scope, scope.owner_id, "grant-second-project-owner"),
        project_id=project_id,
        subject_type="user",
        subject_id=scope.member_id,
        role="owner",
        expires_at=None,
        idempotency_key="grant-second-project-owner",
    )
    governance = MembershipGovernanceService(factory, ProjectRemovalImpactProvider(factory))

    preflight = governance.create_removal_preflight(
        actor_id=scope.owner_id,
        tenant_id=scope.tenant_id,
        user_id=scope.member_id,
        idempotency_key="project-owner-removal-preflight",
    )

    assert preflight.status == "blocked"
    assert preflight.blocking_count == 1


def _seed_saga_partition(
    factory: sessionmaker[Session], scope: ProjectScope, physical_workspace_id: int
) -> UUID:
    placement_id, partition_id = uuid4(), uuid4()
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref=f"saga-db-{physical_workspace_id}",
                object_store_ref=f"saga-object-{physical_workspace_id}",
                kms_key_ref=f"saga-kms-{physical_workspace_id}",
                official_schema_revision="c4d5e6f7a8b9",
                capacity_class="shared",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key=str(physical_workspace_id),
                placement_generation=1,
                source_revision="saga-revision",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
    return partition_id


def test_binding_and_saga_reject_unreviewed_runtime_target_before_persistence(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    _projects, authorizer, project_id = _create_restricted_project(factory, scope)
    partition_id = _seed_saga_partition(factory, scope, 89)
    binding_service = RuntimeBindingService(
        factory, authorizer, _binding_policy("reviewed-revision")
    )
    saga_service = RuntimeBindingSagaService(factory, binding_service, authorizer)
    owner = _context(scope, scope.owner_id, "unreviewed-runtime-target")

    with pytest.raises(LifecycleError) as binding_error:
        binding_service.bind_resource(
            owner,
            project_id=project_id,
            runtime_partition_id=partition_id,
            resource_type="conversation",
            runtime_resource_id="must-not-persist",
            saas_resource_id=uuid4(),
            expected_partition_generation=1,
            idempotency_key="unreviewed-binding",
        )
    assert binding_error.value.code == "source_revision_not_allowed"

    with pytest.raises(LifecycleError) as saga_error:
        saga_service.start(
            owner,
            project_id=project_id,
            runtime_partition_id=partition_id,
            resource_type="conversation",
            saas_resource_id=uuid4(),
            idempotency_key="unreviewed-saga",
        )
    assert saga_error.value.code == "source_revision_not_allowed"

    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RuntimeResourceBindingRecord)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(RuntimeBindingSagaRecord)) == 0
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.idempotency_key.in_(
                        ("unreviewed-binding", "unreviewed-saga")
                    )
                )
            )
            == 0
        )


def test_binding_saga_resumes_after_crash_window_without_duplicate_runtime_resource(
    project_control_plane, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory, scope = project_control_plane
    _projects, authorizer, project_id = _create_restricted_project(factory, scope)
    partition_id = _seed_saga_partition(factory, scope, 97)
    binding_service = RuntimeBindingService(factory, authorizer, _binding_policy("saga-revision"))
    saga_service = RuntimeBindingSagaService(factory, binding_service, authorizer)
    owner = _context(scope, scope.owner_id, "saga-crash-window")
    resource_id = uuid4()
    started = saga_service.start(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        saas_resource_id=resource_id,
        idempotency_key="saga-crash-start",
    )
    replay = saga_service.start(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        saas_resource_id=resource_id,
        idempotency_key="saga-crash-start",
    )
    assert replay.saga_id == started.saga_id and replay.replayed
    provisioner = _IdempotentProvisioner()

    def _crash_after_provision(*_args, **_kwargs):
        raise RuntimeError("injected crash after official commit")

    monkeypatch.setattr(saga_service, "_mark_runtime_created", _crash_after_provision)
    with pytest.raises(RuntimeError, match="injected crash"):
        saga_service.advance(owner, saga_id=started.saga_id, provisioner=provisioner)
    with factory() as db:
        pending = db.get(RuntimeBindingSagaRecord, started.saga_id)
        assert pending is not None and pending.status == "pending"

    resumed_service = RuntimeBindingSagaService(factory, binding_service, authorizer)
    runtime_created = resumed_service.advance(
        owner, saga_id=started.saga_id, provisioner=provisioner
    )
    assert runtime_created.status == "runtime_created"
    bound = resumed_service.advance(owner, saga_id=started.saga_id, provisioner=provisioner)
    assert bound.status == "bound"
    assert bound.binding_id is not None
    assert len(provisioner.provision_calls) == 2
    assert len(provisioner.resources) == 1
    terminal = resumed_service.advance(owner, saga_id=started.saga_id, provisioner=provisioner)
    assert terminal.status == "bound" and terminal.replayed


def test_binding_saga_compensates_official_resource_when_binding_conflicts(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    _projects, authorizer, project_id = _create_restricted_project(factory, scope)
    partition_id = _seed_saga_partition(factory, scope, 101)
    binding_service = RuntimeBindingService(factory, authorizer, _binding_policy("saga-revision"))
    owner = _context(scope, scope.owner_id, "saga-compensation")
    resource_id = uuid4()
    binding_service.bind_resource(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        runtime_resource_id="already-bound-runtime-resource",
        saas_resource_id=resource_id,
        expected_partition_generation=1,
        idempotency_key="saga-existing-binding",
    )
    saga_service = RuntimeBindingSagaService(factory, binding_service, authorizer)
    started = saga_service.start(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        saas_resource_id=resource_id,
        idempotency_key="saga-compensating-start",
    )
    provisioner = _IdempotentProvisioner()
    assert (
        saga_service.advance(owner, saga_id=started.saga_id, provisioner=provisioner).status
        == "runtime_created"
    )

    with pytest.raises(LifecycleError) as exc_info:
        saga_service.advance(owner, saga_id=started.saga_id, provisioner=provisioner)
    assert exc_info.value.code == "binding_saga_compensated"
    with factory() as db:
        saga = db.get(RuntimeBindingSagaRecord, started.saga_id)
        assert saga is not None and saga.status == "compensated"
        assert saga.binding_id is None
    assert len(provisioner.compensation_calls) == 1


def test_binding_saga_marks_failed_when_compensation_needs_operator(
    project_control_plane,
) -> None:
    factory, scope = project_control_plane
    _projects, authorizer, project_id = _create_restricted_project(factory, scope)
    partition_id = _seed_saga_partition(factory, scope, 103)
    binding_service = RuntimeBindingService(factory, authorizer, _binding_policy("saga-revision"))
    owner = _context(scope, scope.owner_id, "saga-compensation-failure")
    resource_id = uuid4()
    binding_service.bind_resource(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        runtime_resource_id="conflicting-runtime-resource",
        saas_resource_id=resource_id,
        expected_partition_generation=1,
        idempotency_key="saga-failed-existing-binding",
    )
    saga_service = RuntimeBindingSagaService(factory, binding_service, authorizer)
    started = saga_service.start(
        owner,
        project_id=project_id,
        runtime_partition_id=partition_id,
        resource_type="conversation",
        saas_resource_id=resource_id,
        idempotency_key="saga-failed-start",
    )
    provisioner = _IdempotentProvisioner()
    provisioner.fail_compensation = True
    saga_service.advance(owner, saga_id=started.saga_id, provisioner=provisioner)

    with pytest.raises(LifecycleError) as exc_info:
        saga_service.advance(owner, saga_id=started.saga_id, provisioner=provisioner)
    assert exc_info.value.code == "binding_saga_compensation_failed"
    with factory() as db:
        saga = db.get(RuntimeBindingSagaRecord, started.saga_id)
        assert saga is not None and saga.status == "failed"
        assert saga.last_error == "injected compensation failure"
