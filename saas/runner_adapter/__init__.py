"""Runner-owned physical adapters behind the SaaS control-plane boundary."""

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
    "FilesystemRecoveryArtifactStore",
    "PhysicalCheckpoint",
    "PhysicalWorktree",
    "RepositoryMirrorResolver",
    "RunnerWorktreeAdapter",
    "RunnerWorktreeAdapterError",
    "StaticRepositoryMirrorResolver",
    "WorktreeLifecycleAuthority",
]
