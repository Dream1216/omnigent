"""Runtime Placement/Partition projection into the official workspace scope.

The records accepted here must come from trusted SaaS repositories after
authorization. Public request payloads must never construct them directly.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from omnigent.db.db_models import workspace_scope


class PartitionStatus(StrEnum):
    """Lifecycle states that affect runtime routing."""

    PROVISIONING = "provisioning"
    ACTIVE = "active"
    DRAINING = "draining"
    MIGRATING = "migrating"
    QUARANTINED = "quarantined"
    RETIRED = "retired"


class BindingStatus(StrEnum):
    """Lifecycle states shared by identity and resource bindings."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class RuntimeResolutionError(PermissionError):
    """Fail-closed runtime projection error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Authorized SaaS request facts; selectors are already resolved."""

    actor_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID | None
    user_security_version: int
    tenant_membership_version: int
    space_membership_version: int
    trace_id: str

    def __post_init__(self) -> None:
        if (
            min(
                self.user_security_version,
                self.tenant_membership_version,
                self.space_membership_version,
            )
            < 1
        ):
            raise ValueError("security and membership versions must be positive")
        if not self.trace_id.strip():
            raise ValueError("trace_id must not be empty")


@dataclass(frozen=True, slots=True)
class RuntimePartition:
    """Server-owned route to one Placement-local Omnigent workspace."""

    id: UUID
    tenant_id: UUID
    space_id: UUID
    placement_id: UUID
    placement_generation: int
    physical_workspace_id: int
    runtime_type: str
    data_region: str
    source_revision: str
    adapter_contract_version: str
    status: PartitionStatus


@dataclass(frozen=True, slots=True)
class RuntimeIdentityAlias:
    """Stable SaaS user projected to an upstream-compatible user key."""

    runtime_partition_id: UUID
    user_id: UUID
    runtime_user_key: str
    status: BindingStatus


@dataclass(frozen=True, slots=True)
class RuntimeResourceBinding:
    """Server-owned binding between a SaaS resource and upstream resource."""

    id: UUID
    runtime_partition_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID | None
    resource_type: str
    runtime_resource_id: str
    saas_resource_id: UUID
    partition_generation: int
    binding_generation: int
    status: BindingStatus


@dataclass(frozen=True, slots=True)
class RuntimeContext:
    """Derived execution projection consumed by compatibility adapters."""

    actor_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID | None
    user_security_version: int
    tenant_membership_version: int
    space_membership_version: int
    runtime_partition_id: UUID
    placement_id: UUID
    placement_generation: int
    binding_generation: int
    data_region: str
    physical_workspace_id: int
    runtime_user_key: str
    runtime_type: str
    source_revision: str
    adapter_contract_version: str
    trace_id: str


_current_runtime_context: ContextVar[RuntimeContext | None] = ContextVar(
    "saas_runtime_context", default=None
)


def _deny(code: str, message: str) -> None:
    raise RuntimeResolutionError(code, message)


def resolve_runtime_context(
    request: RequestContext,
    partition: RuntimePartition,
    identity_alias: RuntimeIdentityAlias,
    resource_binding: RuntimeResourceBinding,
) -> RuntimeContext:
    """Derive a fail-closed RuntimeContext from trusted repository records."""

    if partition.status is not PartitionStatus.ACTIVE:
        _deny("partition_not_active", "runtime partition is not active")
    if partition.physical_workspace_id <= 0:
        _deny("default_workspace_forbidden", "SaaS runtime cannot use workspace 0")
    if partition.placement_generation < 1:
        _deny("partition_generation_invalid", "placement generation must be positive")
    if partition.tenant_id != request.tenant_id:
        _deny("tenant_scope_mismatch", "runtime partition belongs to another tenant")
    if partition.space_id != request.space_id:
        _deny("space_scope_mismatch", "runtime partition belongs to another space")

    if resource_binding.status is not BindingStatus.ACTIVE:
        _deny("resource_binding_not_active", "runtime resource binding is not active")
    if resource_binding.runtime_partition_id != partition.id:
        _deny("binding_partition_mismatch", "resource binding targets another partition")
    if resource_binding.tenant_id != request.tenant_id:
        _deny("binding_tenant_mismatch", "resource binding belongs to another tenant")
    if resource_binding.space_id != request.space_id:
        _deny("binding_space_mismatch", "resource binding belongs to another space")
    if resource_binding.project_id != request.project_id:
        _deny("binding_project_mismatch", "resource binding belongs to another project")
    if resource_binding.partition_generation != partition.placement_generation:
        _deny("binding_generation_stale", "resource binding targets a stale generation")
    if resource_binding.binding_generation < 1:
        _deny("binding_generation_invalid", "binding generation must be positive")

    if identity_alias.status is not BindingStatus.ACTIVE:
        _deny("identity_alias_not_active", "runtime identity alias is not active")
    if identity_alias.runtime_partition_id != partition.id:
        _deny("identity_partition_mismatch", "runtime identity targets another partition")
    if identity_alias.user_id != request.actor_id:
        _deny("identity_actor_mismatch", "runtime identity belongs to another actor")
    if not identity_alias.runtime_user_key.strip():
        _deny("identity_key_invalid", "runtime user key must not be empty")

    for code, value in (
        ("runtime_type_invalid", partition.runtime_type),
        ("data_region_invalid", partition.data_region),
        ("source_revision_invalid", partition.source_revision),
        ("adapter_contract_invalid", partition.adapter_contract_version),
    ):
        if not value.strip():
            _deny(code, "runtime revision metadata must not be empty")

    return RuntimeContext(
        actor_id=request.actor_id,
        tenant_id=request.tenant_id,
        space_id=request.space_id,
        project_id=request.project_id,
        user_security_version=request.user_security_version,
        tenant_membership_version=request.tenant_membership_version,
        space_membership_version=request.space_membership_version,
        runtime_partition_id=partition.id,
        placement_id=partition.placement_id,
        placement_generation=partition.placement_generation,
        binding_generation=resource_binding.binding_generation,
        data_region=partition.data_region,
        physical_workspace_id=partition.physical_workspace_id,
        runtime_user_key=identity_alias.runtime_user_key,
        runtime_type=partition.runtime_type,
        source_revision=partition.source_revision,
        adapter_contract_version=partition.adapter_contract_version,
        trace_id=request.trace_id,
    )


def current_runtime_context() -> RuntimeContext:
    """Return the bound RuntimeContext or fail when called outside the adapter."""

    context = _current_runtime_context.get()
    if context is None:
        raise RuntimeError("runtime context is not bound")
    return context


@contextlib.contextmanager
def bind_runtime_context(context: RuntimeContext) -> Iterator[RuntimeContext]:
    """Bind downstream placement facts and the official workspace ContextVar."""

    token = _current_runtime_context.set(context)
    try:
        with workspace_scope(context.physical_workspace_id):
            yield context
    finally:
        _current_runtime_context.reset(token)
