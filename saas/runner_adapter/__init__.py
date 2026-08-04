"""Runner-owned physical adapters behind the SaaS control-plane boundary."""

from saas.runner_adapter.isolation import (
    ContainmentVerifier,
    IsolationAuthority,
    PreparedRunnerIsolation,
    RunnerIsolationAdapter,
    RunnerIsolationAdapterError,
)
from saas.runner_adapter.worktrees import (
    CheckpointArtifact,
    FilesystemRecoveryArtifactStore,
    PhysicalCheckpoint,
    PhysicalWorktree,
    RepositoryMirrorResolver,
    RunnerWorktreeAdapter,
    RunnerWorktreeAdapterError,
    StaticRepositoryMirrorResolver,
    WorktreeLifecycleAuthority,
)

__all__ = [
    "CheckpointArtifact",
    "ContainmentVerifier",
    "FilesystemRecoveryArtifactStore",
    "IsolationAuthority",
    "PhysicalCheckpoint",
    "PhysicalWorktree",
    "PreparedRunnerIsolation",
    "RepositoryMirrorResolver",
    "RunnerIsolationAdapter",
    "RunnerIsolationAdapterError",
    "RunnerWorktreeAdapter",
    "RunnerWorktreeAdapterError",
    "StaticRepositoryMirrorResolver",
    "WorktreeLifecycleAuthority",
]
