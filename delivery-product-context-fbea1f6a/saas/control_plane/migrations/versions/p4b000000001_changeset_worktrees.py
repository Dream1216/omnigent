"""Create P4 Repository, ChangeSet, quota, and fenced Worktree authority.

Revision ID: p4b000000001
Revises: p4a000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p4b000000001"
down_revision: str | None = "p4a000000001"
branch_labels: str | None = None
depends_on: str | None = None

_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_governance', 'member')"
_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE = "NULLIF(current_setting('app.space_id', true), '')::uuid"


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def _updated_at() -> sa.Column:
    return sa.Column(
        "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def _scope_columns() -> tuple[sa.Column, sa.Column, sa.Column]:
    return (
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "saas_repositories",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("source_binding_key", sa.String(256), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=False),
        sa.Column("default_branch", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_repository_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("status IN ('active', 'archived')", name="ck_repository_status"),
        sa.CheckConstraint("length(provider) > 0", name="ck_repository_provider_nonempty"),
        sa.CheckConstraint(
            "length(source_binding_key) > 0", name="ck_repository_binding_nonempty"
        ),
        sa.CheckConstraint("length(display_name) > 0", name="ck_repository_name_nonempty"),
        sa.CheckConstraint("length(default_branch) > 0", name="ck_repository_branch_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_repository_version"),
        sa.PrimaryKeyConstraint("id"),
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
    )
    op.create_index(
        "ix_repository_project_status",
        "saas_repositories",
        ("tenant_id", "space_id", "project_id", "status"),
    )

    op.create_table(
        "saas_changeset_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_changeset_group_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'completed', 'abandoned')", name="ck_changeset_group_status"
        ),
        sa.CheckConstraint("length(title) > 0", name="ck_changeset_group_title_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_changeset_group_version"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_changeset_group_scope"
        ),
    )
    op.create_index(
        "ix_changeset_group_creator_status",
        "saas_changeset_groups",
        ("tenant_id", "space_id", "created_by", "status"),
    )

    op.create_table(
        "saas_changesets",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("repository_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("base_revision", sa.String(128), nullable=False),
        sa.Column("head_revision", sa.String(128), nullable=True),
        sa.Column("branch_ref", sa.String(256), nullable=False),
        sa.Column("recovery_artifact_ref", sa.String(256), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
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
            "status IN ('open', 'checkpointed', 'committed', 'abandoned', 'quarantined')",
            name="ck_changeset_status",
        ),
        sa.CheckConstraint("length(base_revision) > 0", name="ck_changeset_base_nonempty"),
        sa.CheckConstraint(
            "head_revision IS NULL OR length(head_revision) > 0",
            name="ck_changeset_head_nonempty",
        ),
        sa.CheckConstraint("length(branch_ref) > 0", name="ck_changeset_branch_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_changeset_version"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "repository_id", name="uq_changeset_group_repository"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_changeset_scope"
        ),
    )
    op.create_index(
        "ix_changeset_creator_status",
        "saas_changesets",
        ("tenant_id", "space_id", "created_by", "status"),
    )

    op.create_table(
        "saas_worktree_quotas",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("max_active_instances", sa.Integer(), nullable=False),
        sa.Column("max_active_writers", sa.Integer(), nullable=False),
        sa.Column("max_reserved_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_lease_seconds", sa.Integer(), nullable=False),
        sa.Column("max_lifetime_seconds", sa.Integer(), nullable=False),
        sa.Column("gc_grace_seconds", sa.Integer(), nullable=False),
        sa.Column("active_instances", sa.Integer(), nullable=False),
        sa.Column("active_writers", sa.Integer(), nullable=False),
        sa.Column("reserved_bytes", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "space_id", "project_id", name="uq_worktree_quota_project"
        ),
    )

    op.create_table(
        "saas_worktree_instances",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("change_set_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("opaque_runtime_key", sa.String(96), nullable=False),
        sa.Column("access_mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("lease_generation", sa.BigInteger(), nullable=False),
        sa.Column("run_fence_token", sa.BigInteger(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_token_hash", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("maximum_lifetime_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reserved_bytes", sa.BigInteger(), nullable=False),
        sa.Column("actual_bytes", sa.BigInteger(), nullable=False),
        sa.Column("dirty", sa.Boolean(), nullable=False),
        sa.Column("recovery_artifact_ref", sa.String(256), nullable=True),
        sa.Column("environment_snapshot_ref", sa.String(256), nullable=True),
        sa.Column("event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarantine_reason", sa.String(256), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
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
        sa.CheckConstraint(
            "access_mode IN ('writer', 'readonly')", name="ck_worktree_access_mode"
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'materializing', 'ready', 'checkpointing', "
            "'rebuild_pending', 'released', 'quarantined', 'gc_eligible', 'deleted')",
            name="ck_worktree_status",
        ),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("opaque_runtime_key"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_worktree_instance_scope"
        ),
    )
    op.create_index(
        "uq_worktree_active_writer",
        "saas_worktree_instances",
        ("change_set_id",),
        unique=True,
        sqlite_where=sa.text(
            "access_mode = 'writer' AND status IN "
            "('reserved', 'materializing', 'ready', 'checkpointing')"
        ),
        postgresql_where=sa.text(
            "access_mode = 'writer' AND status IN "
            "('reserved', 'materializing', 'ready', 'checkpointing')"
        ),
    )
    op.create_index(
        "ix_worktree_scope_status",
        "saas_worktree_instances",
        ("tenant_id", "space_id", "project_id", "status"),
    )
    op.create_index("ix_worktree_run_status", "saas_worktree_instances", ("run_id", "status"))
    op.create_index(
        "ix_worktree_lease_expiry", "saas_worktree_instances", ("status", "lease_expires_at")
    )
    op.create_index("ix_worktree_gc", "saas_worktree_instances", ("status", "released_at"))

    op.create_table(
        "saas_worktree_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("worktree_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("trace_id", sa.String(128), nullable=False),
        _created_at(),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("worktree_id", "sequence", name="uq_worktree_event_sequence"),
    )
    op.create_index(
        "ix_worktree_event_replay", "saas_worktree_events", ("worktree_id", "sequence")
    )

    _install_postgresql_rls()


def _install_postgresql_rls() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    app_scope = f"({_PLATFORM} OR {_EXECUTOR} OR (tenant_id = {_TENANT} AND space_id = {_SPACE}))"
    governance_scope = (
        f"({_GOVERNANCE} AND tenant_id = {_TENANT} AND ({_SPACE} IS NULL OR space_id = {_SPACE}))"
    )
    for table in (
        "saas_repositories",
        "saas_changeset_groups",
        "saas_changesets",
        "saas_worktree_quotas",
        "saas_worktree_instances",
        "saas_worktree_events",
    ):
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" '
            f"FOR ALL USING ({app_scope}) WITH CHECK ({app_scope})"
        )
        op.execute(
            f'CREATE POLICY "rls_{table}_governance_read" ON "{table}" '
            f"FOR SELECT USING ({governance_scope})"
        )
    _install_immutability_guards()


def _install_immutability_guards() -> None:
    op.execute(
        """
        CREATE FUNCTION saas_guard_repository_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(NEW.id, NEW.tenant_id, NEW.space_id, NEW.project_id,
                   NEW.created_by, NEW.provider, NEW.source_binding_key)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.tenant_id, OLD.space_id, OLD.project_id,
                   OLD.created_by, OLD.provider, OLD.source_binding_key) THEN
                RAISE EXCEPTION 'Repository identity and source binding are immutable';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        'CREATE TRIGGER "trg_saas_repositories_immutable" '
        'BEFORE UPDATE ON "saas_repositories" FOR EACH ROW '
        "EXECUTE FUNCTION saas_guard_repository_immutable()"
    )
    op.execute(
        """
        CREATE FUNCTION saas_guard_changeset_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(NEW.id, NEW.tenant_id, NEW.space_id, NEW.project_id,
                   NEW.group_id, NEW.repository_id, NEW.created_by,
                   NEW.base_revision, NEW.branch_ref)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.tenant_id, OLD.space_id, OLD.project_id,
                   OLD.group_id, OLD.repository_id, OLD.created_by,
                   OLD.base_revision, OLD.branch_ref) THEN
                RAISE EXCEPTION 'ChangeSet scope, Repository, and base revision are immutable';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        'CREATE TRIGGER "trg_saas_changesets_immutable" '
        'BEFORE UPDATE ON "saas_changesets" FOR EACH ROW '
        "EXECUTE FUNCTION saas_guard_changeset_immutable()"
    )
    op.execute(
        """
        CREATE FUNCTION saas_guard_worktree_instance_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(NEW.id, NEW.tenant_id, NEW.space_id, NEW.project_id,
                   NEW.change_set_id, NEW.run_id, NEW.runner_id, NEW.created_by,
                   NEW.opaque_runtime_key, NEW.access_mode, NEW.run_fence_token,
                   NEW.runner_connection_generation, NEW.maximum_lifetime_at,
                   NEW.reserved_bytes, NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.tenant_id, OLD.space_id, OLD.project_id,
                   OLD.change_set_id, OLD.run_id, OLD.runner_id, OLD.created_by,
                   OLD.opaque_runtime_key, OLD.access_mode, OLD.run_fence_token,
                   OLD.runner_connection_generation, OLD.maximum_lifetime_at,
                   OLD.reserved_bytes, OLD.created_at) THEN
                RAISE EXCEPTION 'Worktree scope and execution bindings are immutable';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        'CREATE TRIGGER "trg_saas_worktree_instances_immutable" '
        'BEFORE UPDATE ON "saas_worktree_instances" FOR EACH ROW '
        "EXECUTE FUNCTION saas_guard_worktree_instance_immutable()"
    )
    op.execute(
        """
        CREATE FUNCTION saas_reject_worktree_event_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Worktree lifecycle events are append-only';
        END
        $$
        """
    )
    op.execute(
        'CREATE TRIGGER "trg_saas_worktree_events_append_only" '
        'BEFORE UPDATE OR DELETE ON "saas_worktree_events" FOR EACH ROW '
        "EXECUTE FUNCTION saas_reject_worktree_event_mutation()"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            'DROP TRIGGER IF EXISTS "trg_saas_worktree_events_append_only" '
            'ON "saas_worktree_events"'
        )
        op.execute(
            'DROP TRIGGER IF EXISTS "trg_saas_worktree_instances_immutable" '
            'ON "saas_worktree_instances"'
        )
        op.execute('DROP TRIGGER IF EXISTS "trg_saas_changesets_immutable" ON "saas_changesets"')
        op.execute(
            'DROP TRIGGER IF EXISTS "trg_saas_repositories_immutable" ON "saas_repositories"'
        )
        op.execute("DROP FUNCTION IF EXISTS saas_reject_worktree_event_mutation()")
        op.execute("DROP FUNCTION IF EXISTS saas_guard_worktree_instance_immutable()")
        op.execute("DROP FUNCTION IF EXISTS saas_guard_changeset_immutable()")
        op.execute("DROP FUNCTION IF EXISTS saas_guard_repository_immutable()")
    op.drop_index("ix_worktree_event_replay", table_name="saas_worktree_events")
    op.drop_table("saas_worktree_events")
    op.drop_index("ix_worktree_gc", table_name="saas_worktree_instances")
    op.drop_index("ix_worktree_lease_expiry", table_name="saas_worktree_instances")
    op.drop_index("ix_worktree_run_status", table_name="saas_worktree_instances")
    op.drop_index("ix_worktree_scope_status", table_name="saas_worktree_instances")
    op.drop_index("uq_worktree_active_writer", table_name="saas_worktree_instances")
    op.drop_table("saas_worktree_instances")
    op.drop_table("saas_worktree_quotas")
    op.drop_index("ix_changeset_creator_status", table_name="saas_changesets")
    op.drop_table("saas_changesets")
    op.drop_index("ix_changeset_group_creator_status", table_name="saas_changeset_groups")
    op.drop_table("saas_changeset_groups")
    op.drop_index("ix_repository_project_status", table_name="saas_repositories")
    op.drop_table("saas_repositories")
