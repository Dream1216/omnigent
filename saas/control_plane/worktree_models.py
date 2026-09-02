"""Durable P4 Repository, ChangeSet, and leased Worktree control-plane facts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

REPOSITORY_STATUSES = ("active", "archived")
CHANGE_SET_GROUP_STATUSES = ("open", "completed", "abandoned")
CHANGE_SET_STATUSES = ("open", "checkpointed", "committed", "abandoned", "quarantined")
WORKTREE_ACCESS_MODES = ("writer", "readonly")
WORKTREE_STATUSES = (
    "reserved",
    "materializing",
    "ready",
    "checkpointing",
    "rebuild_pending",
    "released",
    "quarantined",
    "gc_eligible",
    "deleted",
)
ACTIVE_WORKTREE_STATUSES = frozenset({"reserved", "materializing", "ready", "checkpointing"})


class RepositoryRecord(SaasBase):
    """Credential-free source binding owned by one Project."""

    __tablename__ = "saas_repositories"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_binding_key: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    default_branch: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_repository_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(REPOSITORY_STATUSES)})", name="ck_repository_status"
        ),
        sa.CheckConstraint("length(provider) > 0", name="ck_repository_provider_nonempty"),
        sa.CheckConstraint(
            "length(source_binding_key) > 0", name="ck_repository_binding_nonempty"
        ),
        sa.CheckConstraint("length(display_name) > 0", name="ck_repository_name_nonempty"),
        sa.CheckConstraint("length(default_branch) > 0", name="ck_repository_branch_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_repository_version"),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "source_binding_key",
            name="uq_repository_project_binding",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_repository_scope"
        ),
        sa.Index("ix_repository_project_status", "tenant_id", "space_id", "project_id", "status"),
    )


class ChangeSetGroupRecord(SaasBase):
    """Atomic user intent grouping one ChangeSet per Repository."""

    __tablename__ = "saas_changeset_groups"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    title: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="open")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_changeset_group_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(CHANGE_SET_GROUP_STATUSES)})",
            name="ck_changeset_group_status",
        ),
        sa.CheckConstraint("length(title) > 0", name="ck_changeset_group_title_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_changeset_group_version"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_changeset_group_scope"
        ),
        sa.Index(
            "ix_changeset_group_creator_status",
            "tenant_id",
            "space_id",
            "created_by",
            "status",
        ),
    )


class ChangeSetRecord(SaasBase):
    """Durable branch intent pinned to one Repository and immutable base revision."""

    __tablename__ = "saas_changesets"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    group_id: Mapped[UUID] = mapped_column(nullable=False)
    repository_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    base_revision: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    head_revision: Mapped[str | None] = mapped_column(sa.String(128))
    branch_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    recovery_artifact_ref: Mapped[str | None] = mapped_column(sa.String(256))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="open")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("group_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_changeset_groups.id",
                "saas_changeset_groups.tenant_id",
                "saas_changeset_groups.space_id",
                "saas_changeset_groups.project_id",
            ),
            name="fk_changeset_group_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("repository_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_repositories.id",
                "saas_repositories.tenant_id",
                "saas_repositories.space_id",
                "saas_repositories.project_id",
            ),
            name="fk_changeset_repository_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(CHANGE_SET_STATUSES)})", name="ck_changeset_status"
        ),
        sa.CheckConstraint("length(base_revision) > 0", name="ck_changeset_base_nonempty"),
        sa.CheckConstraint(
            "head_revision IS NULL OR length(head_revision) > 0",
            name="ck_changeset_head_nonempty",
        ),
        sa.CheckConstraint("length(branch_ref) > 0", name="ck_changeset_branch_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_changeset_version"),
        sa.UniqueConstraint("group_id", "repository_id", name="uq_changeset_group_repository"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_changeset_scope"
        ),
        sa.Index("ix_changeset_creator_status", "tenant_id", "space_id", "created_by", "status"),
    )


class WorktreeQuotaRecord(SaasBase):
    """Project Worktree limits and transactionally maintained active reservations."""

    __tablename__ = "saas_worktree_quotas"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    max_active_instances: Mapped[int] = mapped_column(nullable=False)
    max_active_writers: Mapped[int] = mapped_column(nullable=False)
    max_reserved_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    max_lease_seconds: Mapped[int] = mapped_column(nullable=False)
    max_lifetime_seconds: Mapped[int] = mapped_column(nullable=False)
    gc_grace_seconds: Mapped[int] = mapped_column(nullable=False)
    active_instances: Mapped[int] = mapped_column(nullable=False, default=0)
    active_writers: Mapped[int] = mapped_column(nullable=False, default=0)
    reserved_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_worktree_quota_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("max_active_instances > 0", name="ck_worktree_quota_instances"),
        sa.CheckConstraint("max_active_writers > 0", name="ck_worktree_quota_writers"),
        sa.CheckConstraint(
            "max_active_writers <= max_active_instances", name="ck_worktree_quota_writer_limit"
        ),
        sa.CheckConstraint("max_reserved_bytes > 0", name="ck_worktree_quota_bytes"),
        sa.CheckConstraint("max_lease_seconds > 0", name="ck_worktree_quota_lease"),
        sa.CheckConstraint(
            "max_lifetime_seconds >= max_lease_seconds", name="ck_worktree_quota_lifetime"
        ),
        sa.CheckConstraint("gc_grace_seconds >= 0", name="ck_worktree_quota_gc_grace"),
        sa.CheckConstraint(
            "active_instances >= 0 AND active_instances <= max_active_instances",
            name="ck_worktree_quota_active_instances",
        ),
        sa.CheckConstraint(
            "active_writers >= 0 AND active_writers <= max_active_writers",
            name="ck_worktree_quota_active_writers",
        ),
        sa.CheckConstraint(
            "reserved_bytes >= 0 AND reserved_bytes <= max_reserved_bytes",
            name="ck_worktree_quota_reserved_bytes",
        ),
        sa.CheckConstraint("version > 0", name="ck_worktree_quota_version"),
        sa.UniqueConstraint(
            "tenant_id", "space_id", "project_id", name="uq_worktree_quota_project"
        ),
    )


class WorktreeInstanceRecord(SaasBase):
    """Leased, rebuildable physical checkout projection; never stores a host path."""

    __tablename__ = "saas_worktree_instances"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    change_set_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    runner_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT"), nullable=False
    )
    created_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    created_by_service_account_id: Mapped[UUID | None] = mapped_column()
    opaque_runtime_key: Mapped[str] = mapped_column(sa.String(96), nullable=False, unique=True)
    access_mode: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="reserved")
    lease_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    run_fence_token: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    lease_token_hash: Mapped[str | None] = mapped_column(sa.String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    maximum_lifetime_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    reserved_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    actual_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    dirty: Mapped[bool] = mapped_column(nullable=False, default=False)
    recovery_artifact_ref: Mapped[str | None] = mapped_column(sa.String(256))
    environment_snapshot_ref: Mapped[str | None] = mapped_column(sa.String(256))
    event_sequence: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    released_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    quarantine_reason: Mapped[str | None] = mapped_column(sa.String(256))
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("change_set_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_changesets.id",
                "saas_changesets.tenant_id",
                "saas_changesets.space_id",
                "saas_changesets.project_id",
            ),
            name="fk_worktree_changeset_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_worktree_run_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "created_by_service_account_id"),
            (
                "saas_service_accounts.tenant_id",
                "saas_service_accounts.space_id",
                "saas_service_accounts.project_id",
                "saas_service_accounts.id",
            ),
            name="fk_worktree_service_account_actor",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(created_by IS NOT NULL) <> (created_by_service_account_id IS NOT NULL)",
            name="ck_worktree_actor_xor",
        ),
        sa.CheckConstraint(
            f"access_mode IN ({_values(WORKTREE_ACCESS_MODES)})",
            name="ck_worktree_access_mode",
        ),
        sa.CheckConstraint(f"status IN ({_values(WORKTREE_STATUSES)})", name="ck_worktree_status"),
        sa.CheckConstraint("lease_generation > 0", name="ck_worktree_lease_generation"),
        sa.CheckConstraint("run_fence_token > 0", name="ck_worktree_run_fence"),
        sa.CheckConstraint(
            "runner_connection_generation > 0", name="ck_worktree_runner_generation"
        ),
        sa.CheckConstraint(
            "lease_token_hash IS NULL OR length(lease_token_hash) = 64",
            name="ck_worktree_lease_hash",
        ),
        sa.CheckConstraint("reserved_bytes > 0", name="ck_worktree_reserved_bytes"),
        sa.CheckConstraint("actual_bytes >= 0", name="ck_worktree_actual_bytes"),
        sa.CheckConstraint("event_sequence >= 0", name="ck_worktree_event_sequence"),
        sa.CheckConstraint(
            "maximum_lifetime_at > created_at", name="ck_worktree_maximum_lifetime"
        ),
        sa.CheckConstraint(
            "(status IN ('reserved', 'materializing', 'ready', 'checkpointing') "
            "AND lease_token_hash IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND released_at IS NULL AND deleted_at IS NULL) OR "
            "(status NOT IN ('reserved', 'materializing', 'ready', 'checkpointing'))",
            name="ck_worktree_active_lease",
        ),
        sa.CheckConstraint(
            "access_mode = 'writer' OR dirty = false", name="ck_worktree_readonly_clean"
        ),
        sa.CheckConstraint(
            "(status = 'quarantined' AND quarantine_reason IS NOT NULL) OR "
            "(status <> 'quarantined')",
            name="ck_worktree_quarantine_reason",
        ),
        sa.CheckConstraint(
            "(status = 'deleted' AND deleted_at IS NOT NULL) OR (status <> 'deleted')",
            name="ck_worktree_deleted_at",
        ),
        sa.Index(
            "uq_worktree_active_writer",
            "change_set_id",
            unique=True,
            sqlite_where=sa.text(
                "access_mode = 'writer' AND status IN "
                "('reserved', 'materializing', 'ready', 'checkpointing')"
            ),
            postgresql_where=sa.text(
                "access_mode = 'writer' AND status IN "
                "('reserved', 'materializing', 'ready', 'checkpointing')"
            ),
        ),
        sa.Index(
            "uq_worktree_runner_run_fence_v1",
            "run_id",
            "run_fence_token",
            unique=True,
        ),
        sa.Index("ix_worktree_scope_status", "tenant_id", "space_id", "project_id", "status"),
        sa.Index("ix_worktree_run_status", "run_id", "status"),
        sa.Index(
            "ix_worktree_service_account_created",
            "tenant_id",
            "created_by_service_account_id",
            "created_at",
        ),
        sa.Index("ix_worktree_lease_expiry", "status", "lease_expires_at"),
        sa.Index("ix_worktree_gc", "status", "released_at"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_worktree_instance_scope"
        ),
    )


class WorktreeEventRecord(SaasBase):
    """Credential-free append-only Worktree lifecycle evidence."""

    __tablename__ = "saas_worktree_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    worktree_id: Mapped[UUID] = mapped_column(nullable=False)
    sequence: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    trace_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("worktree_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_worktree_instances.id",
                "saas_worktree_instances.tenant_id",
                "saas_worktree_instances.space_id",
                "saas_worktree_instances.project_id",
            ),
            name="fk_worktree_event_instance",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("sequence > 0", name="ck_worktree_event_sequence"),
        sa.CheckConstraint("length(event_type) > 0", name="ck_worktree_event_type"),
        sa.CheckConstraint("length(trace_id) > 0", name="ck_worktree_event_trace"),
        sa.UniqueConstraint("worktree_id", "sequence", name="uq_worktree_event_sequence"),
        sa.Index("ix_worktree_event_replay", "worktree_id", "sequence"),
    )
