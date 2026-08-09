"""Stable downstream contracts for integrating the Omnigent runtime."""

from saas.compatibility.runtime_partition import (
    BindingStatus,
    PartitionStatus,
    RequestContext,
    RuntimeContext,
    RuntimeIdentityAlias,
    RuntimePartition,
    RuntimeResolutionError,
    RuntimeResourceBinding,
    bind_runtime_context,
    current_runtime_context,
    resolve_runtime_context,
)
from saas.compatibility.store_adapter import (
    OmnigentStoreAdapter,
    StoreAdapterContractError,
    WorkspaceOwnedRecord,
)

__all__ = [
    "BindingStatus",
    "OmnigentStoreAdapter",
    "PartitionStatus",
    "RequestContext",
    "RuntimeContext",
    "RuntimeIdentityAlias",
    "RuntimePartition",
    "RuntimeResolutionError",
    "RuntimeResourceBinding",
    "StoreAdapterContractError",
    "WorkspaceOwnedRecord",
    "bind_runtime_context",
    "current_runtime_context",
    "resolve_runtime_context",
]
