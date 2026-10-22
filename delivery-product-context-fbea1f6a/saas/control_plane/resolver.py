"""Fail-closed server-side membership and runtime placement resolution."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Never
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import (
    BindingStatus,
    PartitionStatus,
    RequestContext,
    RuntimeContext,
    RuntimeIdentityAlias,
    RuntimePartition,
    RuntimeResolutionError,
    RuntimeResourceBinding,
    resolve_runtime_context,
)
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import (
    GlobalUser,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.rls import RlsContext, apply_rls_context


class ControlPlaneResolutionError(PermissionError):
    """Fail-closed control-plane error with a stable internal code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _ScopeFacts:
    user_status: str
    user_security_version: int
    tenant_status: str
    tenant_membership_status: str
    tenant_membership_version: int
    space_status: str
    space_membership_status: str
    space_membership_version: int


@dataclass(frozen=True, slots=True)
class AvailableScope:
    """Logical Context Shell option; physical runtime facts are intentionally absent."""

    tenant_id: UUID
    tenant_slug: str
    tenant_name: str
    tenant_role: str
    tenant_membership_version: int
    space_id: UUID
    space_slug: str
    space_name: str
    space_role: str
    space_membership_version: int
    user_security_version: int


@dataclass(frozen=True, slots=True)
class RuntimeCompatibilityPolicy:
    """Revisions that this deployment may route to official runtimes."""

    runtime_type: str
    allowed_runtime_versions: frozenset[str]
    allowed_source_revisions: frozenset[str]
    allowed_schema_revisions: frozenset[str]
    adapter_contract_version: str

    def __post_init__(self) -> None:
        if not self.runtime_type.strip() or not self.adapter_contract_version.strip():
            raise ValueError("runtime type and adapter contract must not be empty")
        if not all(
            (
                self.allowed_runtime_versions,
                self.allowed_source_revisions,
                self.allowed_schema_revisions,
            )
        ):
            raise ValueError("runtime compatibility revision sets must not be empty")


def load_runtime_compatibility_policy(
    manifest_path: str | Path,
    *,
    runtime_type: str = "omnigent",
) -> RuntimeCompatibilityPolicy:
    """Load the trusted runtime policy from the reviewed upstream manifest."""

    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    return RuntimeCompatibilityPolicy(
        runtime_type=runtime_type,
        allowed_runtime_versions=frozenset((str(manifest["upstream_version"]),)),
        allowed_source_revisions=frozenset((str(manifest["upstream_revision"]),)),
        allowed_schema_revisions=frozenset(
            str(revision) for revision in manifest["official_schema_heads"]
        ),
        adapter_contract_version=str(manifest["adapter_contract_version"]),
    )


class SqlAlchemyContextResolver:
    """Resolve authorized snapshots without accepting runtime placement input."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        compatibility_policy: RuntimeCompatibilityPolicy,
        project_authorizer: ProjectAuthorizer | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._compatibility_policy = compatibility_policy
        self._project_authorizer = project_authorizer

    def list_available_scopes(self, *, actor_id: UUID) -> tuple[AvailableScope, ...]:
        """List only the actor's active logical Tenant/Space memberships."""

        with self._session_factory() as session, session.begin():
            apply_rls_context(session, RlsContext(actor_id=actor_id))
            user = session.get(GlobalUser, actor_id)
            if user is None or user.status != "active" or user.security_version < 1:
                self._deny("user_not_active", "global user is not active")
            rows = session.execute(
                sa.select(
                    Tenant.id,
                    Tenant.slug,
                    Tenant.name,
                    TenantMembership.role,
                    TenantMembership.version,
                    Space.id,
                    Space.slug,
                    Space.name,
                    SpaceMembership.role,
                    SpaceMembership.version,
                )
                .join(TenantMembership, TenantMembership.tenant_id == Tenant.id)
                .join(
                    SpaceMembership,
                    sa.and_(
                        SpaceMembership.tenant_id == Tenant.id,
                        SpaceMembership.user_id == TenantMembership.user_id,
                    ),
                )
                .join(
                    Space,
                    sa.and_(
                        Space.tenant_id == SpaceMembership.tenant_id,
                        Space.id == SpaceMembership.space_id,
                    ),
                )
                .where(
                    TenantMembership.user_id == actor_id,
                    TenantMembership.status == "active",
                    Tenant.status.in_(("trial", "active")),
                    SpaceMembership.status == "active",
                    Space.status == "active",
                )
                .order_by(Tenant.name, Tenant.id, Space.name, Space.id)
            ).all()
            return tuple(
                AvailableScope(
                    tenant_id=tenant_id,
                    tenant_slug=tenant_slug,
                    tenant_name=tenant_name,
                    tenant_role=tenant_role,
                    tenant_membership_version=tenant_version,
                    space_id=space_id,
                    space_slug=space_slug,
                    space_name=space_name,
                    space_role=space_role,
                    space_membership_version=space_version,
                    user_security_version=user.security_version,
                )
                for (
                    tenant_id,
                    tenant_slug,
                    tenant_name,
                    tenant_role,
                    tenant_version,
                    space_id,
                    space_slug,
                    space_name,
                    space_role,
                    space_version,
                ) in rows
            )

    def resolve_request_context(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        trace_id: str,
    ) -> RequestContext:
        """Build a versioned RequestContext from current server-side memberships."""

        with self._session_factory() as session, session.begin():
            apply_rls_context(
                session,
                RlsContext(actor_id=actor_id, tenant_id=tenant_id, space_id=space_id),
            )
            facts = self._load_scope_facts(
                session, actor_id=actor_id, tenant_id=tenant_id, space_id=space_id
            )
            self._require_active_scope(facts)
            return RequestContext(
                actor_id=actor_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=None,
                user_security_version=facts.user_security_version,
                tenant_membership_version=facts.tenant_membership_version,
                space_membership_version=facts.space_membership_version,
                trace_id=trace_id,
            )

    def resolve_existing_resource(
        self,
        request: RequestContext,
        *,
        resource_type: str,
        saas_resource_id: UUID,
        action: str = "project.content.read",
    ) -> RuntimeContext:
        """Resolve one authorized SaaS resource to its trusted runtime context."""

        if not resource_type.strip():
            self._deny("resource_selector_invalid", "resource type must not be empty")
        if request.project_id is not None:
            if self._project_authorizer is None:
                self._deny(
                    "project_authorization_required",
                    "project-scoped resources require a configured Authorizer",
                )
            decision = self._project_authorizer.evaluate(
                request,
                action=action,
                project_id=request.project_id,
                resource_type=resource_type,
                resource_id=saas_resource_id,
                mode="enforce",
            )
            if not decision.allowed:
                self._deny("resource_not_routable", "resource is not accessible")

        with self._session_factory() as session, session.begin():
            apply_rls_context(
                session,
                RlsContext(
                    actor_id=request.actor_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                ),
            )
            facts = self._load_scope_facts(
                session,
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
            )
            self._require_active_scope(facts)
            if (
                request.user_security_version != facts.user_security_version
                or request.tenant_membership_version != facts.tenant_membership_version
                or request.space_membership_version != facts.space_membership_version
            ):
                self._deny(
                    "authorization_snapshot_stale",
                    "security or membership facts changed after context issuance",
                )

            rows = session.execute(
                sa.select(
                    RuntimeResourceBindingRecord,
                    RuntimePartitionRecord,
                    RuntimePlacementRecord,
                    RuntimeIdentityAliasRecord,
                )
                .join(
                    RuntimePartitionRecord,
                    sa.and_(
                        RuntimePartitionRecord.id
                        == RuntimeResourceBindingRecord.runtime_partition_id,
                        RuntimePartitionRecord.tenant_id == RuntimeResourceBindingRecord.tenant_id,
                        RuntimePartitionRecord.space_id == RuntimeResourceBindingRecord.space_id,
                    ),
                )
                .join(
                    RuntimePlacementRecord,
                    RuntimePlacementRecord.id == RuntimePartitionRecord.placement_id,
                )
                .join(
                    RuntimeIdentityAliasRecord,
                    sa.and_(
                        RuntimeIdentityAliasRecord.runtime_partition_id
                        == RuntimePartitionRecord.id,
                        RuntimeIdentityAliasRecord.user_id == request.actor_id,
                    ),
                )
                .where(
                    RuntimeResourceBindingRecord.tenant_id == request.tenant_id,
                    RuntimeResourceBindingRecord.space_id == request.space_id,
                    RuntimeResourceBindingRecord.resource_type == resource_type,
                    RuntimeResourceBindingRecord.saas_resource_id == saas_resource_id,
                    RuntimeResourceBindingRecord.status == BindingStatus.ACTIVE.value,
                )
            ).all()
            if len(rows) != 1:
                self._deny(
                    "resource_not_routable",
                    "resource has no unambiguous active runtime binding",
                )

            binding, partition, placement, identity_alias = rows[0]
            if binding.project_id is not None and request.project_id is None:
                self._deny(
                    "project_authorization_required",
                    "project-scoped resources require an authorized Project context",
                )
            if binding.project_id != request.project_id:
                self._deny("resource_not_routable", "resource is not accessible")
            if placement.status != "active":
                self._deny("placement_not_active", "runtime placement is not active")
            if placement.runtime_type != partition.runtime_type:
                self._deny("placement_runtime_mismatch", "runtime placement type does not match")
            if not placement.data_region.strip():
                self._deny("placement_region_invalid", "runtime placement region is invalid")
            self._require_compatible_runtime(partition, placement)

            physical_workspace_id = self._parse_omnigent_workspace(partition)
            try:
                return resolve_runtime_context(
                    request,
                    RuntimePartition(
                        id=partition.id,
                        tenant_id=partition.tenant_id,
                        space_id=partition.space_id,
                        placement_id=partition.placement_id,
                        placement_generation=partition.placement_generation,
                        physical_workspace_id=physical_workspace_id,
                        runtime_type=partition.runtime_type,
                        data_region=placement.data_region,
                        source_revision=partition.source_revision,
                        adapter_contract_version=partition.adapter_contract_version,
                        status=self._partition_status(partition.status),
                    ),
                    RuntimeIdentityAlias(
                        runtime_partition_id=identity_alias.runtime_partition_id,
                        user_id=identity_alias.user_id,
                        runtime_user_key=identity_alias.runtime_user_key,
                        status=self._binding_status(identity_alias.status),
                    ),
                    RuntimeResourceBinding(
                        id=binding.id,
                        runtime_partition_id=binding.runtime_partition_id,
                        tenant_id=binding.tenant_id,
                        space_id=binding.space_id,
                        project_id=binding.project_id,
                        resource_type=binding.resource_type,
                        runtime_resource_id=binding.runtime_resource_id,
                        saas_resource_id=binding.saas_resource_id,
                        partition_generation=binding.partition_generation,
                        binding_generation=binding.binding_generation,
                        status=self._binding_status(binding.status),
                    ),
                )
            except RuntimeResolutionError as error:
                raise ControlPlaneResolutionError(error.code, str(error)) from error

    def resolve_space_allocation(self, request: RequestContext) -> RuntimeContext:
        """Resolve the single active allocation partition for new Space-scoped work."""

        with self._session_factory() as session, session.begin():
            apply_rls_context(
                session,
                RlsContext(
                    actor_id=request.actor_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                ),
            )
            facts = self._load_scope_facts(
                session,
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
            )
            self._require_active_scope(facts)
            if (
                request.user_security_version != facts.user_security_version
                or request.tenant_membership_version != facts.tenant_membership_version
                or request.space_membership_version != facts.space_membership_version
            ):
                self._deny(
                    "authorization_snapshot_stale",
                    "security or membership facts changed after context issuance",
                )
            rows = session.execute(
                sa.select(
                    RuntimePartitionRecord,
                    RuntimePlacementRecord,
                    RuntimeIdentityAliasRecord,
                )
                .join(
                    RuntimePlacementRecord,
                    RuntimePlacementRecord.id == RuntimePartitionRecord.placement_id,
                )
                .join(
                    RuntimeIdentityAliasRecord,
                    sa.and_(
                        RuntimeIdentityAliasRecord.runtime_partition_id
                        == RuntimePartitionRecord.id,
                        RuntimeIdentityAliasRecord.user_id == request.actor_id,
                    ),
                )
                .where(
                    RuntimePartitionRecord.tenant_id == request.tenant_id,
                    RuntimePartitionRecord.space_id == request.space_id,
                    RuntimePartitionRecord.status == "active",
                    RuntimeIdentityAliasRecord.status == "active",
                )
            ).all()
            if len(rows) != 1:
                self._deny(
                    "allocation_partition_ambiguous",
                    "Space must have exactly one active allocation partition",
                )
            partition, placement, identity_alias = rows[0]
            if placement.status != "active":
                self._deny("placement_not_active", "runtime placement is not active")
            if placement.runtime_type != partition.runtime_type:
                self._deny("placement_runtime_mismatch", "runtime placement type does not match")
            self._require_compatible_runtime(partition, placement)
            physical_workspace_id = self._parse_omnigent_workspace(partition)
            return RuntimeContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=None,
                user_security_version=request.user_security_version,
                tenant_membership_version=request.tenant_membership_version,
                space_membership_version=request.space_membership_version,
                runtime_partition_id=partition.id,
                placement_id=partition.placement_id,
                placement_generation=partition.placement_generation,
                binding_generation=partition.placement_generation,
                data_region=placement.data_region,
                physical_workspace_id=physical_workspace_id,
                runtime_user_key=identity_alias.runtime_user_key,
                runtime_type=partition.runtime_type,
                source_revision=partition.source_revision,
                adapter_contract_version=partition.adapter_contract_version,
                trace_id=request.trace_id,
            )

    def _load_scope_facts(
        self,
        session: Session,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
    ) -> _ScopeFacts:
        row = session.execute(
            sa.select(
                GlobalUser.status,
                GlobalUser.security_version,
                Tenant.status,
                TenantMembership.status,
                TenantMembership.version,
                Space.status,
                SpaceMembership.status,
                SpaceMembership.version,
            )
            .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
            .join(Tenant, Tenant.id == TenantMembership.tenant_id)
            .join(
                Space,
                sa.and_(Space.tenant_id == Tenant.id, Space.id == space_id),
            )
            .join(
                SpaceMembership,
                sa.and_(
                    SpaceMembership.tenant_id == Tenant.id,
                    SpaceMembership.space_id == Space.id,
                    SpaceMembership.user_id == GlobalUser.id,
                ),
            )
            .where(
                GlobalUser.id == actor_id,
                Tenant.id == tenant_id,
            )
        ).one_or_none()
        if row is None:
            self._deny("scope_not_authorized", "tenant or space scope is not authorized")
        return _ScopeFacts(*row)

    def _require_active_scope(self, facts: _ScopeFacts) -> None:
        if facts.user_status != "active":
            self._deny("user_not_active", "global user is not active")
        if facts.tenant_status not in {"trial", "active"}:
            self._deny("tenant_not_active", "tenant is not active")
        if facts.tenant_membership_status != "active":
            self._deny("tenant_membership_not_active", "tenant membership is not active")
        if facts.space_status != "active":
            self._deny("space_not_active", "space is not active")
        if facts.space_membership_status != "active":
            self._deny("space_membership_not_active", "space membership is not active")
        if (
            min(
                facts.user_security_version,
                facts.tenant_membership_version,
                facts.space_membership_version,
            )
            < 1
        ):
            self._deny(
                "authorization_version_invalid",
                "security and membership versions must be positive",
            )

    def _parse_omnigent_workspace(self, partition: RuntimePartitionRecord) -> int:
        if partition.runtime_type != "omnigent":
            self._deny("runtime_type_unsupported", "runtime type is not supported")
        try:
            workspace_id = int(partition.physical_partition_key)
        except ValueError:
            self._deny("physical_partition_invalid", "Omnigent workspace id is invalid")
        if str(workspace_id) != partition.physical_partition_key or workspace_id <= 0:
            self._deny("physical_partition_invalid", "Omnigent workspace id is invalid")
        return workspace_id

    def _require_compatible_runtime(
        self,
        partition: RuntimePartitionRecord,
        placement: RuntimePlacementRecord,
    ) -> None:
        policy = self._compatibility_policy
        if partition.runtime_type != policy.runtime_type:
            self._deny("runtime_type_unsupported", "runtime type is not supported")
        if partition.runtime_version not in policy.allowed_runtime_versions:
            self._deny("runtime_version_unsupported", "runtime version is not approved")
        if partition.source_revision not in policy.allowed_source_revisions:
            self._deny("runtime_source_unsupported", "runtime source revision is not approved")
        if placement.official_schema_revision not in policy.allowed_schema_revisions:
            self._deny("runtime_schema_unsupported", "runtime schema revision is not approved")
        if partition.adapter_contract_version != policy.adapter_contract_version:
            self._deny("adapter_contract_unsupported", "adapter contract is not approved")

    def _partition_status(self, status: str) -> PartitionStatus:
        try:
            return PartitionStatus(status)
        except ValueError:
            self._deny("partition_status_invalid", "runtime partition status is invalid")

    def _binding_status(self, status: str) -> BindingStatus:
        try:
            return BindingStatus(status)
        except ValueError:
            self._deny("binding_status_invalid", "runtime binding status is invalid")

    @staticmethod
    def _deny(code: str, message: str) -> Never:
        raise ControlPlaneResolutionError(code, message)
