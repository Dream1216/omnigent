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

__all__ = [
    "BindingStatus",
    "PartitionStatus",
    "RequestContext",
    "RuntimeContext",
    "RuntimeIdentityAlias",
    "RuntimePartition",
    "RuntimeResolutionError",
    "RuntimeResourceBinding",
    "bind_runtime_context",
    "current_runtime_context",
    "resolve_runtime_context",
]
