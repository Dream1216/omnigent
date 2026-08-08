from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    ControlPlaneResolutionError,
    GlobalUser,
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
    load_runtime_compatibility_policy,
)
from saas.control_plane.db_models import ProjectRecord

COMPATIBILITY_POLICY = RuntimeCompatibilityPolicy(
    runtime_type="omnigent",
    allowed_runtime_versions=frozenset(("0.9.0.dev0",)),
    allowed_source_revisions=frozenset(("9dab48b460f37d8a0ed294d1309cd2f843c5cafc",)),
    allowed_schema_revisions=frozenset(("f7a8b9c0d1e2",)),
    adapter_contract_version="0.2.0",
)


@dataclass(frozen=True, slots=True)
class SeededScope:
    actor_id: UUID
    tenant_id: UUID
    space_id: UUID
    saas_resource_id: UUID
    partition_id: UUID
    placement_id: UUID
    other_tenant_id: UUID
    other_space_id: UUID


@pytest.fixture
def control_plane() -> tuple[sessionmaker[Session], SeededScope]:
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
    scope = SeededScope(
        actor_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        saas_resource_id=uuid4(),
        partition_id=uuid4(),
        placement_id=uuid4(),
        other_tenant_id=uuid4(),
        other_space_id=uuid4(),
    )
    with factory.begin() as session:
        session.add(GlobalUser(id=scope.actor_id, status="active", security_version=1))
        session.add_all(
            [
                Tenant(
                    id=scope.tenant_id,
                    slug="tenant-a",
                    name="Tenant A",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
                Tenant(
                    id=scope.other_tenant_id,
                    slug="tenant-b",
                    name="Tenant B",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                Space(
                    id=scope.space_id,
                    tenant_id=scope.tenant_id,
                    slug="engineering",
                    name="Engineering",
                    status="active",
                ),
                Space(
                    id=scope.other_space_id,
                    tenant_id=scope.other_tenant_id,
                    slug="engineering",
                    name="Engineering",
                    status="active",
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                TenantMembership(
                    tenant_id=scope.tenant_id,
                    user_id=scope.actor_id,
                    role="owner",
                    status="active",
                    version=3,
                ),
                TenantMembership(
                    tenant_id=scope.other_tenant_id,
                    user_id=scope.actor_id,
                    role="member",
                    status="active",
                    version=11,
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                SpaceMembership(
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    user_id=scope.actor_id,
                    role="owner",
                    status="active",
                    version=7,
                ),
                SpaceMembership(
                    tenant_id=scope.other_tenant_id,
                    space_id=scope.other_space_id,
                    user_id=scope.actor_id,
                    role="member",
                    status="active",
                    version=13,
                ),
            ]
        )
        session.flush()
        session.add(
            RuntimePlacementRecord(
                id=scope.placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-cluster-a",
                object_store_ref="object-store-a",
                kms_key_ref="kms-key-a",
                official_schema_revision="f7a8b9c0d1e2",
                capacity_class="shared-medium",
                status="active",
            )
        )
        session.flush()
        session.add(
            RuntimePartitionRecord(
                id=scope.partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                placement_id=scope.placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key="41",
                placement_generation=4,
                source_revision="9dab48b460f37d8a0ed294d1309cd2f843c5cafc",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
        session.flush()
        session.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=scope.partition_id,
                user_id=scope.actor_id,
                runtime_user_key="user_7f7b",
                status="active",
            )
        )
        session.flush()
        session.add(
            RuntimeResourceBindingRecord(
                id=uuid4(),
                runtime_partition_id=scope.partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                project_id=None,
                resource_type="conversation",
                runtime_resource_id="conv_123",
                saas_resource_id=scope.saas_resource_id,
                partition_generation=4,
                binding_generation=2,
                status="active",
            )
        )

    yield factory, scope
    engine.dispose()


def _resolver(
    control_plane,
) -> tuple[SqlAlchemyContextResolver, sessionmaker[Session], SeededScope]:
    factory, scope = control_plane
    return SqlAlchemyContextResolver(factory, COMPATIBILITY_POLICY), factory, scope


def test_runtime_policy_loads_from_reviewed_upstream_manifest() -> None:
    root = Path(__file__).resolve().parents[2]
    policy = load_runtime_compatibility_policy(root / "saas/upstream-baseline.json")

    assert policy == COMPATIBILITY_POLICY


def test_server_resolves_membership_versions_and_runtime_placement(control_plane) -> None:
    resolver, _factory, scope = _resolver(control_plane)

    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-p1-resolver",
    )
    runtime = resolver.resolve_existing_resource(
        request,
        resource_type="conversation",
        saas_resource_id=scope.saas_resource_id,
    )

    assert request.tenant_membership_version == 3
    assert request.space_membership_version == 7
    assert request.user_security_version == 1
    assert runtime.runtime_partition_id == scope.partition_id
    assert runtime.placement_id == scope.placement_id
    assert runtime.physical_workspace_id == 41
    assert runtime.runtime_user_key == "user_7f7b"
    assert runtime.binding_generation == 2


def test_space_allocation_resolves_new_work_without_client_placement_input(
    control_plane,
) -> None:
    resolver, _factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-space-allocation",
    )

    runtime = resolver.resolve_space_allocation(request)

    assert runtime.runtime_partition_id == scope.partition_id
    assert runtime.placement_id == scope.placement_id
    assert runtime.physical_workspace_id == 41
    assert runtime.runtime_user_key == "user_7f7b"
    assert runtime.binding_generation == 4


def test_same_user_can_resolve_a_second_tenant_but_not_cross_tenant_resource(
    control_plane,
) -> None:
    resolver, _factory, scope = _resolver(control_plane)
    other_request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.other_tenant_id,
        space_id=scope.other_space_id,
        trace_id="trace-other-tenant",
    )

    assert other_request.tenant_membership_version == 11
    assert other_request.space_membership_version == 13
    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            other_request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "resource_not_routable"


def test_membership_version_change_revokes_issued_snapshot(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-before-role-change",
    )
    with factory.begin() as session:
        membership = session.get(TenantMembership, (scope.tenant_id, scope.actor_id))
        assert membership is not None
        membership.version += 1

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "authorization_snapshot_stale"


def test_user_security_version_change_revokes_issued_snapshot(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-before-security-change",
    )
    with factory.begin() as session:
        user = session.get(GlobalUser, scope.actor_id)
        assert user is not None
        user.security_version += 1

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "authorization_snapshot_stale"


def test_suspended_space_membership_fails_closed(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    with factory.begin() as session:
        membership = session.get(
            SpaceMembership,
            (scope.tenant_id, scope.space_id, scope.actor_id),
        )
        assert membership is not None
        membership.status = "suspended"
        membership.version += 1

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_request_context(
            actor_id=scope.actor_id,
            tenant_id=scope.tenant_id,
            space_id=scope.space_id,
            trace_id="trace-suspended",
        )
    assert exc_info.value.code == "space_membership_not_active"


def test_quarantined_placement_fails_closed(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-quarantined",
    )
    with factory.begin() as session:
        placement = session.get(RuntimePlacementRecord, scope.placement_id)
        assert placement is not None
        placement.status = "quarantined"

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "placement_not_active"


def test_default_or_noncanonical_workspace_key_is_rejected(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-workspace-zero",
    )
    with factory.begin() as session:
        partition = session.get(RuntimePartitionRecord, scope.partition_id)
        assert partition is not None
        partition.physical_partition_key = "0"

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "physical_partition_invalid"


def test_unapproved_runtime_schema_is_rejected(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-stale-schema",
    )
    with factory.begin() as session:
        placement = session.get(RuntimePlacementRecord, scope.placement_id)
        assert placement is not None
        placement.official_schema_revision = "stale-schema"

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "runtime_schema_unsupported"


def test_project_binding_waits_for_project_authorizer(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-project-gate",
    )
    project_id = uuid4()
    with factory.begin() as session:
        session.add(
            ProjectRecord(
                id=project_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                name="Project gate",
                visibility="restricted",
                created_by=scope.actor_id,
                status="active",
                authorization_version=1,
            )
        )
        session.flush()
        binding = session.scalar(
            sa.select(RuntimeResourceBindingRecord).where(
                RuntimeResourceBindingRecord.saas_resource_id == scope.saas_resource_id
            )
        )
        assert binding is not None
        binding.project_id = project_id

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "project_authorization_required"


def test_stale_partition_generation_is_exposed_as_control_plane_error(control_plane) -> None:
    resolver, factory, scope = _resolver(control_plane)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="trace-stale-generation",
    )
    with factory.begin() as session:
        partition = session.get(RuntimePartitionRecord, scope.partition_id)
        assert partition is not None
        partition.placement_generation += 1

    with pytest.raises(ControlPlaneResolutionError) as exc_info:
        resolver.resolve_existing_resource(
            request,
            resource_type="conversation",
            saas_resource_id=scope.saas_resource_id,
        )
    assert exc_info.value.code == "binding_generation_stale"


def test_cross_tenant_space_membership_is_rejected_by_schema(control_plane) -> None:
    _resolver_instance, factory, scope = _resolver(control_plane)
    with pytest.raises(IntegrityError), factory.begin() as session:
        session.add(
            SpaceMembership(
                tenant_id=scope.tenant_id,
                space_id=scope.other_space_id,
                user_id=scope.actor_id,
                role="member",
                status="active",
                version=1,
            )
        )
        session.flush()


def test_only_one_active_binding_exists_for_a_saas_resource(control_plane) -> None:
    _resolver_instance, factory, scope = _resolver(control_plane)
    with pytest.raises(IntegrityError), factory.begin() as session:
        session.add(
            RuntimeResourceBindingRecord(
                id=uuid4(),
                runtime_partition_id=scope.partition_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                project_id=None,
                resource_type="conversation",
                runtime_resource_id="conv_duplicate",
                saas_resource_id=scope.saas_resource_id,
                partition_generation=4,
                binding_generation=3,
                status="active",
            )
        )
        session.flush()
