"""Add machine-native public API execution provenance and receipts.

Revision ID: pc6a00000001
Revises: pc5c00000002
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "pc6a00000001"
down_revision: str | None = "pc5c00000002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE = "NULLIF(current_setting('app.space_id', true), '')::uuid"
_PROJECT = "NULLIF(current_setting('app.project_id', true), '')::uuid"
_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_CREDENTIAL = "NULLIF(current_setting('app.api_credential_id', true), '')::uuid"
_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_APP = "pg_has_role(current_user, 'saas_app', 'member')"
_PUBLIC_API = "current_user = 'saas_public_api'"

_EXECUTION_TABLES = (
    "saas_tasks",
    "saas_execution_sessions",
    "saas_session_tasks",
    "saas_runs",
    "saas_run_events",
    "saas_admission_quotas",
    "saas_quota_reservations",
    "saas_effect_calls",
    "saas_artifacts",
    "saas_run_artifacts",
)


def _add_machine_actor(
    table: str,
    *,
    actor_constraint: str,
    actor_fk: str,
    actor_index: str,
) -> None:
    with op.batch_alter_table(table) as batch:
        batch.add_column(sa.Column("created_by_service_account_id", sa.Uuid(), nullable=True))
        batch.alter_column("created_by", existing_type=sa.Uuid(), nullable=True)
        batch.create_foreign_key(
            actor_fk,
            "saas_service_accounts",
            ["tenant_id", "space_id", "project_id", "created_by_service_account_id"],
            ["tenant_id", "space_id", "project_id", "id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            actor_constraint,
            "(created_by IS NOT NULL) <> (created_by_service_account_id IS NOT NULL)",
        )
        batch.create_index(
            actor_index,
            ["tenant_id", "created_by_service_account_id", "created_at"],
        )


def _drop_machine_actor(
    table: str,
    *,
    actor_constraint: str,
    actor_fk: str,
    actor_index: str,
) -> None:
    with op.batch_alter_table(table) as batch:
        batch.drop_index(actor_index)
        batch.drop_constraint(actor_constraint, type_="check")
        batch.drop_constraint(actor_fk, type_="foreignkey")
        batch.alter_column("created_by", existing_type=sa.Uuid(), nullable=False)
        batch.drop_column("created_by_service_account_id")


def _create_receipts() -> None:
    op.create_table(
        "saas_public_api_mutation_receipts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("service_account_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("idempotency_key_id", sa.String(16), nullable=False),
        sa.Column("idempotency_hmac", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("response_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id"],
            ["saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"],
            name="fk_public_api_receipt_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_account_id"],
            ["saas_service_accounts.tenant_id", "saas_service_accounts.id"],
            name="fk_public_api_receipt_service_account",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["saas_api_credentials.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("length(operation) > 0", name="ck_public_api_receipt_operation"),
        sa.CheckConstraint("length(idempotency_key_id) > 0", name="ck_public_api_receipt_key_id"),
        sa.CheckConstraint(
            "length(idempotency_hmac) = 64", name="ck_public_api_receipt_idempotency"
        ),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_public_api_receipt_request_hash"),
        sa.CheckConstraint(
            "length(resource_type) > 0", name="ck_public_api_receipt_resource_type"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "credential_id",
            "operation",
            "idempotency_key_id",
            "idempotency_hmac",
            name="uq_public_api_receipt_idempotency",
        ),
    )
    op.create_index(
        "ix_public_api_receipt_resource",
        "saas_public_api_mutation_receipts",
        ("tenant_id", "space_id", "project_id", "resource_type", "resource_id"),
    )


def _create_rate_limits() -> None:
    op.create_table(
        "saas_public_api_rate_limits",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("route_class", sa.String(64), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["saas_api_credentials.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("length(route_class) > 0", name="ck_public_api_rate_route"),
        sa.CheckConstraint("request_count > 0", name="ck_public_api_rate_count"),
        sa.CheckConstraint("version > 0", name="ck_public_api_rate_version"),
        sa.PrimaryKeyConstraint("credential_id", "route_class"),
    )
    op.create_index(
        "ix_public_api_rate_tenant_window",
        "saas_public_api_rate_limits",
        ("tenant_id", "window_started_at"),
    )


def _add_run_contract_fields() -> None:
    with op.batch_alter_table("saas_runs") as batch:
        batch.add_column(sa.Column("parent_run_id", sa.Uuid(), nullable=True))
        batch.add_column(
            sa.Column(
                "api_metadata",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch.create_foreign_key(
            "fk_run_parent_scope",
            "saas_runs",
            ["parent_run_id", "tenant_id", "space_id", "project_id"],
            ["id", "tenant_id", "space_id", "project_id"],
            ondelete="RESTRICT",
        )
        batch.create_index("ix_run_parent_created", ["parent_run_id", "created_at"])


def _add_session_task_actor() -> None:
    with op.batch_alter_table("saas_session_tasks") as batch:
        batch.add_column(sa.Column("attached_by_service_account_id", sa.Uuid(), nullable=True))
        batch.alter_column("attached_by", existing_type=sa.Uuid(), nullable=True)
        batch.create_foreign_key(
            "fk_session_task_service_account_actor",
            "saas_service_accounts",
            ["tenant_id", "space_id", "project_id", "attached_by_service_account_id"],
            ["tenant_id", "space_id", "project_id", "id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_session_task_actor_xor",
            "(attached_by IS NOT NULL) <> (attached_by_service_account_id IS NOT NULL)",
        )


def _add_usage_actor() -> None:
    with op.batch_alter_table("saas_usage_events") as batch:
        batch.add_column(sa.Column("service_account_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_usage_event_service_account",
            "saas_service_accounts",
            ["tenant_id", "space_id", "project_id", "service_account_id"],
            ["tenant_id", "space_id", "project_id", "id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_usage_event_actor_not_ambiguous",
            "user_id IS NULL OR service_account_id IS NULL",
        )
        batch.create_check_constraint(
            "ck_usage_event_service_account_scope",
            "service_account_id IS NULL OR (space_id IS NOT NULL AND project_id IS NOT NULL)",
        )


def _exact_credential_project_scope(row_project: str) -> str:
    current = (
        "EXISTS (SELECT 1 FROM saas_api_credentials public_credential "
        "JOIN saas_service_accounts public_account "
        "ON public_account.id = public_credential.service_account_id "
        "AND public_account.tenant_id = public_credential.tenant_id "
        f"WHERE public_credential.id = {_CREDENTIAL} "
        f"AND public_credential.service_account_id = {_ACTOR} "
        "AND public_credential.status = 'active' "
        "AND public_credential.revoked_at IS NULL "
        "AND public_credential.expires_at > CURRENT_TIMESTAMP "
        "AND public_account.status = 'active' "
        "AND public_credential.account_security_version = public_account.security_version "
        f"AND public_account.tenant_id = {_TENANT} "
        f"AND public_account.space_id = {_SPACE} "
        f"AND public_account.project_id = {_PROJECT})"
    )
    return f"({row_project} = {_PROJECT} AND {current})"


def _preflight_postgresql_principal() -> None:
    """Require the operator-owned Public API principal before schema DDL."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    row = (
        bind.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                "FROM pg_roles "
                "WHERE rolname = 'saas_public_api'"
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None or (
        bool(row["rolcanlogin"]),
        bool(row["rolsuper"]),
        bool(row["rolcreatedb"]),
        bool(row["rolcreaterole"]),
        bool(row["rolreplication"]),
        bool(row["rolbypassrls"]),
        bool(row["rolinherit"]),
        int(row["rolconnlimit"]),
        row["rolconfig"] is None,
    ) != (False, False, False, False, False, False, True, -1, True):
        raise RuntimeError(
            "cannot apply pc6a00000001: PostgreSQL principal preflight rejected; "
            "run postgresql_principals.psql before Alembic"
        )
    outgoing_memberships = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "WHERE member.rolname = 'saas_public_api'"
        )
    ).scalar_one()
    if outgoing_memberships:
        raise RuntimeError(
            "cannot apply pc6a00000001: PostgreSQL principal preflight rejected; "
            "run postgresql_principals.psql before Alembic"
        )


def _install_postgresql_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _EXECUTION_TABLES:
        legacy_scope = f"(tenant_id = {_TENANT} AND space_id = {_SPACE})"
        if table == "saas_runs":
            legacy_scope = f"({_APP} AND {legacy_scope})"
        public_scope = (
            f"({_PUBLIC_API} AND tenant_id = {_TENANT} AND space_id = {_SPACE} "
            f"AND {_exact_credential_project_scope(f'{table}.project_id')})"
        )
        legacy_predicate = (
            f"({_PLATFORM} OR {_EXECUTOR} OR "
            f"(NOT ({_PUBLIC_API}) AND {_CREDENTIAL} IS NULL AND {legacy_scope}))"
        )
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_scope" ON "{table}"')
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_public_api_exact" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" FOR ALL '
            f"USING ({legacy_predicate}) WITH CHECK ({legacy_predicate})"
        )
        op.execute(
            f'CREATE POLICY "rls_{table}_public_api_exact" ON "{table}" '
            f"AS PERMISSIVE FOR ALL TO saas_public_api "
            f"USING ({public_scope}) WITH CHECK ({public_scope})"
        )

    receipt_project_scope = _exact_credential_project_scope(
        "saas_public_api_mutation_receipts.project_id"
    )
    receipt_scope = (
        f"({_PLATFORM} OR ({_PUBLIC_API} AND tenant_id = {_TENANT} AND space_id = {_SPACE} "
        f"AND project_id = {_PROJECT} AND credential_id = {_CREDENTIAL} "
        "AND service_account_id = "
        f"{_ACTOR} AND {receipt_project_scope}))"
    )
    op.execute('ALTER TABLE "saas_public_api_mutation_receipts" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_public_api_mutation_receipts" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY "rls_public_api_mutation_receipts_exact" '
        'ON "saas_public_api_mutation_receipts" FOR ALL '
        f"USING ({receipt_scope}) WITH CHECK ({receipt_scope})"
    )
    rate_scope = (
        f"({_PLATFORM} OR ({_PUBLIC_API} AND tenant_id = {_TENANT} "
        f"AND credential_id = {_CREDENTIAL} "
        "AND EXISTS (SELECT 1 FROM saas_api_credentials rate_credential "
        "JOIN saas_service_accounts rate_account "
        "ON rate_account.id = rate_credential.service_account_id "
        "AND rate_account.tenant_id = rate_credential.tenant_id "
        f"WHERE rate_credential.id = {_CREDENTIAL} "
        f"AND rate_credential.service_account_id = {_ACTOR} "
        "AND rate_credential.status = 'active' "
        "AND rate_credential.revoked_at IS NULL "
        "AND rate_credential.expires_at > CURRENT_TIMESTAMP "
        "AND rate_account.status = 'active' "
        "AND rate_credential.account_security_version = rate_account.security_version "
        f"AND rate_account.tenant_id = {_TENANT} "
        f"AND rate_account.space_id = {_SPACE} "
        f"AND rate_account.project_id = {_PROJECT})))"
    )
    op.execute('ALTER TABLE "saas_public_api_rate_limits" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_public_api_rate_limits" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY "rls_public_api_rate_limits_exact" '
        'ON "saas_public_api_rate_limits" FOR ALL '
        f"USING ({rate_scope}) WITH CHECK ({rate_scope})"
    )
    op.execute(
        'CREATE POLICY "rls_service_accounts_public_api_exact" '
        'ON "saas_service_accounts" AS RESTRICTIVE FOR SELECT USING ('
        f"NOT ({_PUBLIC_API}) OR (id = {_ACTOR} AND tenant_id = {_TENANT} "
        f"AND space_id = {_SPACE} AND project_id = {_PROJECT}))"
    )
    op.execute(
        'CREATE POLICY "rls_api_credentials_public_api_exact" '
        'ON "saas_api_credentials" AS RESTRICTIVE FOR SELECT USING ('
        f"NOT ({_PUBLIC_API}) OR (id = {_CREDENTIAL} AND service_account_id = {_ACTOR} "
        f"AND tenant_id = {_TENANT}))"
    )
    # Tenant/Space scope policies contain actor-membership subqueries.  PostgreSQL
    # checks privileges for every referenced relation while planning, even when
    # the direct tenant/space branch is sufficient.  Give the public role only
    # the content-blind columns required to plan those policies and make the
    # membership rows unconditionally invisible to that role.
    op.execute(
        'CREATE POLICY "rls_tenant_memberships_public_api_hidden" '
        'ON "saas_tenant_memberships" AS RESTRICTIVE FOR SELECT '
        f"USING (NOT ({_PUBLIC_API}))"
    )
    op.execute(
        'CREATE POLICY "rls_space_memberships_public_api_hidden" '
        'ON "saas_space_memberships" AS RESTRICTIVE FOR SELECT '
        f"USING (NOT ({_PUBLIC_API}))"
    )
    op.execute(
        """
        CREATE FUNCTION saas_reject_machine_actor_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.created_by_service_account_id IS DISTINCT FROM
                  OLD.created_by_service_account_id THEN
                RAISE EXCEPTION 'execution actor provenance is immutable';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    for table in (
        "saas_tasks",
        "saas_runs",
        "saas_artifacts",
        "saas_worktree_instances",
    ):
        op.execute(
            f'CREATE TRIGGER "trg_{table}_actor_immutable" '
            f'BEFORE UPDATE OF created_by, created_by_service_account_id ON "{table}" '
            "FOR EACH ROW EXECUTE FUNCTION saas_reject_machine_actor_mutation()"
        )
    op.execute(
        """
        CREATE FUNCTION saas_reject_session_task_actor_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.attached_by IS DISTINCT FROM OLD.attached_by
               OR NEW.attached_by_service_account_id IS DISTINCT FROM
                  OLD.attached_by_service_account_id THEN
                RAISE EXCEPTION 'session task actor provenance is immutable';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        'CREATE TRIGGER "trg_saas_session_tasks_actor_immutable" '
        "BEFORE UPDATE OF attached_by, attached_by_service_account_id "
        'ON "saas_session_tasks" FOR EACH ROW '
        "EXECUTE FUNCTION saas_reject_session_task_actor_mutation()"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION saas_guard_worktree_instance_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(NEW.id, NEW.tenant_id, NEW.space_id, NEW.project_id,
                   NEW.change_set_id, NEW.run_id, NEW.runner_id, NEW.created_by,
                   NEW.created_by_service_account_id, NEW.opaque_runtime_key,
                   NEW.access_mode, NEW.run_fence_token,
                   NEW.runner_connection_generation, NEW.maximum_lifetime_at,
                   NEW.reserved_bytes, NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.tenant_id, OLD.space_id, OLD.project_id,
                   OLD.change_set_id, OLD.run_id, OLD.runner_id, OLD.created_by,
                   OLD.created_by_service_account_id, OLD.opaque_runtime_key,
                   OLD.access_mode, OLD.run_fence_token,
                   OLD.runner_connection_generation, OLD.maximum_lifetime_at,
                   OLD.reserved_bytes, OLD.created_at) THEN
                RAISE EXCEPTION 'Worktree scope and execution bindings are immutable';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute('DROP POLICY IF EXISTS "rls_usage_events_metering_insert" ON "saas_usage_events"')
    op.execute(
        """
        CREATE POLICY "rls_usage_events_metering_insert"
        ON "saas_usage_events" FOR INSERT WITH CHECK (
          pg_has_role(current_user, 'saas_metering', 'member')
          AND EXISTS (
            SELECT 1 FROM saas_capability_tokens capability
            WHERE capability.token_hash =
              NULLIF(current_setting('app.capability_token_hash', true), '')
            AND capability.tenant_id = saas_usage_events.tenant_id
            AND capability.space_id = saas_usage_events.space_id
            AND capability.project_id = saas_usage_events.project_id
            AND capability.run_id = saas_usage_events.run_id
          )
          AND saas_usage_events.session_id IS NOT DISTINCT FROM
            NULLIF(current_setting('app.metering_session_id', true), '')::uuid
          AND (
            (saas_usage_events.user_id =
               NULLIF(current_setting('app.metering_user_id', true), '')::uuid
             AND saas_usage_events.service_account_id IS NULL)
            OR
            (saas_usage_events.user_id IS NULL
             AND saas_usage_events.service_account_id =
               NULLIF(current_setting('app.metering_service_account_id', true), '')::uuid)
          )
          AND idempotency_key =
            NULLIF(current_setting('app.metering_idempotency_key', true), '')
          AND provider = NULLIF(current_setting('app.metering_provider', true), '')
          AND provider_request_id =
            NULLIF(current_setting('app.metering_provider_request_id', true), '')
          AND meter = NULLIF(current_setting('app.metering_meter', true), '')
        )
        """
    )


def upgrade() -> None:
    """Install direct Service Account provenance without a shadow GlobalUser."""

    _preflight_postgresql_principal()
    with op.batch_alter_table("saas_service_accounts") as batch:
        batch.create_unique_constraint(
            "uq_service_account_project_identity",
            ["tenant_id", "space_id", "project_id", "id"],
        )
    _add_machine_actor(
        "saas_tasks",
        actor_constraint="ck_task_actor_xor",
        actor_fk="fk_task_service_account_actor",
        actor_index="ix_task_service_account_created",
    )
    _add_session_task_actor()
    _add_machine_actor(
        "saas_runs",
        actor_constraint="ck_run_actor_xor",
        actor_fk="fk_run_service_account_actor",
        actor_index="ix_run_service_account_created",
    )
    _add_run_contract_fields()
    _add_machine_actor(
        "saas_artifacts",
        actor_constraint="ck_artifact_actor_xor",
        actor_fk="fk_artifact_service_account_actor",
        actor_index="ix_artifact_service_account_created",
    )
    _add_machine_actor(
        "saas_worktree_instances",
        actor_constraint="ck_worktree_actor_xor",
        actor_fk="fk_worktree_service_account_actor",
        actor_index="ix_worktree_service_account_created",
    )
    _add_usage_actor()
    _create_receipts()
    _create_rate_limits()
    _install_postgresql_security()


def _assert_machine_rows_absent() -> None:
    bind = op.get_bind()
    for table in ("saas_tasks", "saas_runs", "saas_artifacts", "saas_worktree_instances"):
        count = bind.execute(
            sa.text(
                f'SELECT count(*) FROM "{table}" WHERE created_by_service_account_id IS NOT NULL'
            )
        ).scalar_one()
        if count:
            raise RuntimeError(
                "cannot downgrade public API actor provenance while machine-authored rows exist"
            )
    attached_count = bind.execute(
        sa.text(
            "SELECT count(*) FROM saas_session_tasks "
            "WHERE attached_by_service_account_id IS NOT NULL"
        )
    ).scalar_one()
    if attached_count:
        raise RuntimeError(
            "cannot downgrade public API actor provenance while machine session links exist"
        )
    usage_count = bind.execute(
        sa.text("SELECT count(*) FROM saas_usage_events WHERE service_account_id IS NOT NULL")
    ).scalar_one()
    if usage_count:
        raise RuntimeError(
            "cannot downgrade public API actor provenance while machine usage rows exist"
        )


def _restore_postgresql_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _EXECUTION_TABLES:
        legacy_scope = f"(tenant_id = {_TENANT} AND space_id = {_SPACE})"
        if table == "saas_runs":
            legacy_scope = f"({_APP} AND {legacy_scope})"
        predicate = f"({_PLATFORM} OR {_EXECUTOR} OR {legacy_scope})"
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_public_api_exact" ON "{table}"')
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_scope" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" FOR ALL '
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
    op.execute(
        'DROP POLICY IF EXISTS "rls_api_credentials_public_api_exact" ON "saas_api_credentials"'
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_service_accounts_public_api_exact" ON "saas_service_accounts"'
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_space_memberships_public_api_hidden" '
        'ON "saas_space_memberships"'
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_tenant_memberships_public_api_hidden" '
        'ON "saas_tenant_memberships"'
    )
    op.execute(
        'DROP TRIGGER IF EXISTS "trg_saas_session_tasks_actor_immutable" ON "saas_session_tasks"'
    )
    for table in (
        "saas_tasks",
        "saas_runs",
        "saas_artifacts",
        "saas_worktree_instances",
    ):
        op.execute(f'DROP TRIGGER IF EXISTS "trg_{table}_actor_immutable" ON "{table}"')
    op.execute("DROP FUNCTION IF EXISTS saas_reject_session_task_actor_mutation()")
    op.execute("DROP FUNCTION IF EXISTS saas_reject_machine_actor_mutation()")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_public_api') THEN
                EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE '
                    'saas_public_api_mutation_receipts, saas_public_api_rate_limits, '
                    'saas_tenants, saas_spaces, saas_projects, saas_service_accounts, '
                    'saas_api_credentials, saas_tenant_memberships, '
                    'saas_space_memberships, saas_tasks, saas_execution_sessions, '
                    'saas_session_tasks, saas_runs, saas_run_events, '
                    'saas_admission_quotas, saas_quota_reservations, '
                    'saas_control_plane_outbox, saas_platform_role_assignments, '
                    'saas_platform_support_sessions, saas_secret_access_leases, '
                    'saas_preview_leases, saas_runner_certificates, '
                    'saas_capability_tokens FROM saas_public_api';
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION saas_guard_worktree_instance_immutable()
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
    op.execute('DROP POLICY IF EXISTS "rls_usage_events_metering_insert" ON "saas_usage_events"')
    op.execute(
        """
        CREATE POLICY "rls_usage_events_metering_insert"
        ON "saas_usage_events" FOR INSERT WITH CHECK (
          pg_has_role(current_user, 'saas_metering', 'member')
          AND EXISTS (
            SELECT 1 FROM saas_capability_tokens capability
            WHERE capability.token_hash =
              NULLIF(current_setting('app.capability_token_hash', true), '')
            AND capability.tenant_id = saas_usage_events.tenant_id
            AND capability.space_id = saas_usage_events.space_id
            AND capability.project_id = saas_usage_events.project_id
            AND capability.run_id = saas_usage_events.run_id
          )
          AND saas_usage_events.session_id IS NOT DISTINCT FROM
            NULLIF(current_setting('app.metering_session_id', true), '')::uuid
          AND saas_usage_events.user_id =
            NULLIF(current_setting('app.metering_user_id', true), '')::uuid
          AND idempotency_key =
            NULLIF(current_setting('app.metering_idempotency_key', true), '')
          AND provider = NULLIF(current_setting('app.metering_provider', true), '')
          AND provider_request_id =
            NULLIF(current_setting('app.metering_provider_request_id', true), '')
          AND meter = NULLIF(current_setting('app.metering_meter', true), '')
        )
        """
    )


def downgrade() -> None:
    """Remove public API provenance only when no machine-authored facts remain."""

    _assert_machine_rows_absent()
    _restore_postgresql_security()
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            'DROP POLICY IF EXISTS "rls_public_api_rate_limits_exact" '
            'ON "saas_public_api_rate_limits"'
        )
        op.execute('ALTER TABLE "saas_public_api_rate_limits" NO FORCE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "saas_public_api_rate_limits" DISABLE ROW LEVEL SECURITY')
        op.execute(
            'DROP POLICY IF EXISTS "rls_public_api_mutation_receipts_exact" '
            'ON "saas_public_api_mutation_receipts"'
        )
        op.execute('ALTER TABLE "saas_public_api_mutation_receipts" NO FORCE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "saas_public_api_mutation_receipts" DISABLE ROW LEVEL SECURITY')
    op.drop_index(
        "ix_public_api_rate_tenant_window",
        table_name="saas_public_api_rate_limits",
    )
    op.drop_table("saas_public_api_rate_limits")
    op.drop_index(
        "ix_public_api_receipt_resource",
        table_name="saas_public_api_mutation_receipts",
    )
    op.drop_table("saas_public_api_mutation_receipts")
    with op.batch_alter_table("saas_usage_events") as batch:
        batch.drop_constraint("ck_usage_event_service_account_scope", type_="check")
        batch.drop_constraint("ck_usage_event_actor_not_ambiguous", type_="check")
        batch.drop_constraint("fk_usage_event_service_account", type_="foreignkey")
        batch.drop_column("service_account_id")
    _drop_machine_actor(
        "saas_worktree_instances",
        actor_constraint="ck_worktree_actor_xor",
        actor_fk="fk_worktree_service_account_actor",
        actor_index="ix_worktree_service_account_created",
    )
    _drop_machine_actor(
        "saas_artifacts",
        actor_constraint="ck_artifact_actor_xor",
        actor_fk="fk_artifact_service_account_actor",
        actor_index="ix_artifact_service_account_created",
    )
    _drop_machine_actor(
        "saas_runs",
        actor_constraint="ck_run_actor_xor",
        actor_fk="fk_run_service_account_actor",
        actor_index="ix_run_service_account_created",
    )
    with op.batch_alter_table("saas_runs") as batch:
        batch.drop_index("ix_run_parent_created")
        batch.drop_constraint("fk_run_parent_scope", type_="foreignkey")
        batch.drop_column("api_metadata")
        batch.drop_column("parent_run_id")
    with op.batch_alter_table("saas_session_tasks") as batch:
        batch.drop_constraint("ck_session_task_actor_xor", type_="check")
        batch.drop_constraint("fk_session_task_service_account_actor", type_="foreignkey")
        batch.alter_column("attached_by", existing_type=sa.Uuid(), nullable=False)
        batch.drop_column("attached_by_service_account_id")
    _drop_machine_actor(
        "saas_tasks",
        actor_constraint="ck_task_actor_xor",
        actor_fk="fk_task_service_account_actor",
        actor_index="ix_task_service_account_created",
    )
    with op.batch_alter_table("saas_service_accounts") as batch:
        batch.drop_constraint("uq_service_account_project_identity", type_="unique")
