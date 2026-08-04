"""Runner-owned physical adapters behind the SaaS control-plane boundary."""

from saas.runner_adapter.containment import LinuxCgroupV2ContainmentVerifier
from saas.runner_adapter.isolation import (
    ContainmentVerifier,
    IsolationAuthority,
    LaunchGrantAuthority,
    PreparedRunnerIsolation,
    RunnerIsolationAdapter,
    RunnerIsolationAdapterError,
    SecretRedemptionAuthority,
    reap_orphaned_secret_directories,
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
    "LaunchGrantAuthority",
    "LinuxCgroupV2ContainmentVerifier",
    "PhysicalCheckpoint",
    "PhysicalWorktree",
    "PreparedRunnerIsolation",
    "RepositoryMirrorResolver",
    "RunnerIsolationAdapter",
    "RunnerIsolationAdapterError",
    "RunnerWorktreeAdapter",
    "RunnerWorktreeAdapterError",
    "SecretRedemptionAuthority",
    "StaticRepositoryMirrorResolver",
    "WorktreeLifecycleAuthority",
    "reap_orphaned_secret_directories",
]
