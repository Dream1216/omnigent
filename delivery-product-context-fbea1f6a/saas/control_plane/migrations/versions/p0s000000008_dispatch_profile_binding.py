"""Persist the server-selected execution and egress profile on each Run dispatch.

Revision ID: p0s000000008
Revises: p0s000000007
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000008"
down_revision: str | None = "p0s000000007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE_DRAIN_REQUIRED = (
    "cannot apply p0s000000008: pre-upgrade dispatch drain required; "
    "saas_run_dispatches must be empty"
)
_DOWNGRADE_DRAIN_REQUIRED = (
    "cannot downgrade p0s000000008: pre-downgrade dispatch drain required; "
    "saas_run_dispatches must be empty"
)
_EXECUTOR_POLICY = "rls_saas_{table}_dispatch_executor_select"
_EXECUTOR_LOCK_POLICY = "rls_saas_{table}_dispatch_executor_lock"
_EXECUTOR_SCOPE = (
    "pg_has_role(current_user, 'saas_executor', 'member') "
    "AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid "
    "AND space_id = NULLIF(current_setting('app.space_id', true), '')::uuid "
    "AND project_id = NULLIF(current_setting('app.project_id', true), '')::uuid"
)
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_TENANT_SETTING = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE_SETTING = "NULLIF(current_setting('app.space_id', true), '')::uuid"
_PROJECT_SETTING = "NULLIF(current_setting('app.project_id', true), '')::uuid"
_ROUTE_BINDING_SCOPE = (
    f"{_EXECUTOR} AND tenant_id = {_TENANT_SETTING} AND space_id = {_SPACE_SETTING} "
    f"AND project_id = {_PROJECT_SETTING}"
)
_ROUTE_PARTITION_SCOPE = (
    f"{_EXECUTOR} AND tenant_id = {_TENANT_SETTING} AND space_id = {_SPACE_SETTING} "
    "AND EXISTS (SELECT 1 FROM public.saas_runtime_resource_bindings AS route_binding "
    "WHERE route_binding.runtime_partition_id = saas_runtime_partitions.id "
    "AND route_binding.tenant_id = saas_runtime_partitions.tenant_id "
    "AND route_binding.space_id = saas_runtime_partitions.space_id "
    f"AND route_binding.project_id = {_PROJECT_SETTING})"
)
_ROUTE_PLACEMENT_SCOPE = (
    f"{_EXECUTOR} AND EXISTS ("
    "SELECT 1 FROM public.saas_runtime_partitions AS route_partition "
    "JOIN public.saas_runtime_resource_bindings AS route_binding ON "
    "route_binding.runtime_partition_id = route_partition.id "
    "AND route_binding.tenant_id = route_partition.tenant_id "
    "AND route_binding.space_id = route_partition.space_id "
    "WHERE route_partition.placement_id = saas_runtime_placements.id "
    f"AND route_partition.tenant_id = {_TENANT_SETTING} "
    f"AND route_partition.space_id = {_SPACE_SETTING} "
    f"AND route_binding.project_id = {_PROJECT_SETTING})"
)
_ROUTE_POOL_SCOPE = _ROUTE_PLACEMENT_SCOPE.replace(
    "saas_runtime_placements.id", "saas_runner_pools.placement_id"
)
_EXECUTOR_ROUTE_SCOPES = {
    "saas_runtime_resource_bindings": _ROUTE_BINDING_SCOPE,
    "saas_runtime_partitions": _ROUTE_PARTITION_SCOPE,
    "saas_runtime_placements": _ROUTE_PLACEMENT_SCOPE,
    "saas_runner_pools": _ROUTE_POOL_SCOPE,
}
_FINGERPRINT = "NULLIF(current_setting('app.presented_certificate_fingerprint', true), '')"
_PURPOSE = "NULLIF(current_setting('app.presented_certificate_purpose', true), '')"
_CURRENT_CERTIFICATE = (
    "certificate_not_before <= CURRENT_TIMESTAMP "
    "AND certificate_not_after > CURRENT_TIMESTAMP "
    "AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP))"
)
_RUNNER_CONTROL_DOWNGRADE_BLOCKED = (
    "cannot downgrade p0s000000008: runner_control certificates must be revoked "
    "and removed by an explicitly authorized lifecycle migration"
)


def _require_dispatch_drain(*, failure_message: str) -> None:
    """Freeze writers and reject a dispatch population that cannot be converted.

    p0s7 did not persist the execution/egress binding selected for a dispatch,
    while downgrading would erase that binding from p0s8 rows.  Requiring an
    empty table in both directions is the only lossless transition.

    PostgreSQL's ACCESS EXCLUSIVE lock is deliberately acquired before the
    emptiness check and retained by the surrounding Alembic transaction through
    the schema changes.  The table owner temporarily relaxes FORCE RLS only while
    holding that lock so an empty result cannot be forged by policy visibility;
    rejection restores FORCE RLS here and successful callers restore it after
    completing the schema transition.  The SQLite no-op UPDATE takes its database
    writer lock before the same check; SQLite remains a local/test migration target.
    """

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("LOCK TABLE public.saas_run_dispatches IN ACCESS EXCLUSIVE MODE")
        op.execute("ALTER TABLE public.saas_run_dispatches NO FORCE ROW LEVEL SECURITY")
        occupied = bind.execute(
            sa.text("SELECT 1 FROM public.saas_run_dispatches LIMIT 1")
        ).first()
    else:
        bind.exec_driver_sql("UPDATE saas_run_dispatches SET updated_at = updated_at WHERE 1 = 0")
        occupied = bind.execute(sa.text("SELECT 1 FROM saas_run_dispatches LIMIT 1")).first()
    if occupied is not None:
        if bind.dialect.name == "postgresql":
            op.execute("ALTER TABLE public.saas_run_dispatches FORCE ROW LEVEL SECURITY")
        raise RuntimeError(failure_message)


def _require_pre_upgrade_dispatch_drain() -> None:
    _require_dispatch_drain(failure_message=_UPGRADE_DRAIN_REQUIRED)


def _require_pre_downgrade_dispatch_drain() -> None:
    _require_dispatch_drain(failure_message=_DOWNGRADE_DRAIN_REQUIRED)


def _restore_postgresql_force_rls() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE public.saas_run_dispatches FORCE ROW LEVEL SECURITY")


def _install_postgresql_executor_profile_policies() -> None:
    """Expose and lock only the exact Run scope needed by the executor."""

    if op.get_bind().dialect.name != "postgresql":
        return
    for table in ("saas_egress_policies", "saas_execution_profiles"):
        suffix = table.removeprefix("saas_")
        policy = _EXECUTOR_POLICY.format(table=suffix)
        lock_policy = _EXECUTOR_LOCK_POLICY.format(table=suffix)
        op.execute(
            f'CREATE POLICY "{policy}" ON public."{table}" FOR SELECT USING ({_EXECUTOR_SCOPE})'
        )
        op.execute(
            f'CREATE POLICY "{lock_policy}" ON public."{table}" '
            f"FOR UPDATE USING ({_EXECUTOR_SCOPE}) WITH CHECK (false)"
        )
    op.execute(
        'CREATE POLICY "rls_saas_secret_bindings_dispatch_executor_select" '
        'ON public."saas_secret_bindings" '
        f"FOR SELECT USING ({_EXECUTOR_SCOPE})"
    )
    for table, scope in _EXECUTOR_ROUTE_SCOPES.items():
        suffix = table.removeprefix("saas_")
        select_policy = _EXECUTOR_POLICY.format(table=suffix)
        restrictive_select_policy = f"{select_policy}_restrictive"
        lock_policy = _EXECUTOR_LOCK_POLICY.format(table=suffix)
        deny_policy = f"rls_saas_{suffix}_dispatch_executor_mutation_deny"
        # Placement/partition/binding reads must be restricted to one Project.
        # Runner pools intentionally retain their pre-existing global executor
        # SELECT policy: fleet readiness has no Project context.  SELECT ... FOR
        # SHARE still intersects the exact Project-scoped UPDATE policy below.
        if table != "saas_runner_pools":
            op.execute(
                f'CREATE POLICY "{select_policy}" ON public."{table}" '
                f"FOR SELECT TO saas_executor USING ({scope})"
            )
            op.execute(
                f'CREATE POLICY "{restrictive_select_policy}" ON public."{table}" '
                f"AS RESTRICTIVE FOR SELECT TO saas_executor USING ({scope})"
            )
        op.execute(
            f'CREATE POLICY "{lock_policy}" ON public."{table}" '
            f"FOR UPDATE TO saas_executor USING ({scope}) WITH CHECK (false)"
        )
        op.execute(
            f'CREATE POLICY "{deny_policy}" ON public."{table}" AS RESTRICTIVE '
            f"FOR UPDATE TO saas_executor USING ({scope}) WITH CHECK (false)"
        )


def _drop_postgresql_executor_profile_policies() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        'DROP POLICY IF EXISTS "rls_saas_secret_bindings_dispatch_executor_select" '
        'ON public."saas_secret_bindings"'
    )
    for table in reversed(tuple(_EXECUTOR_ROUTE_SCOPES)):
        suffix = table.removeprefix("saas_")
        select_policy = _EXECUTOR_POLICY.format(table=suffix)
        restrictive_select_policy = f"{select_policy}_restrictive"
        lock_policy = _EXECUTOR_LOCK_POLICY.format(table=suffix)
        deny_policy = f"rls_saas_{suffix}_dispatch_executor_mutation_deny"
        op.execute(f'DROP POLICY IF EXISTS "{deny_policy}" ON public."{table}"')
        op.execute(f'DROP POLICY IF EXISTS "{lock_policy}" ON public."{table}"')
        op.execute(f'DROP POLICY IF EXISTS "{restrictive_select_policy}" ON public."{table}"')
        op.execute(f'DROP POLICY IF EXISTS "{select_policy}" ON public."{table}"')
    for table in ("saas_execution_profiles", "saas_egress_policies"):
        suffix = table.removeprefix("saas_")
        policy = _EXECUTOR_POLICY.format(table=suffix)
        lock_policy = _EXECUTOR_LOCK_POLICY.format(table=suffix)
        op.execute(f'DROP POLICY IF EXISTS "{lock_policy}" ON public."{table}"')
        op.execute(f'DROP POLICY IF EXISTS "{policy}" ON public."{table}"')


def _install_runner_control_certificate_purpose() -> None:
    with op.batch_alter_table("saas_runner_certificates") as batch:
        batch.drop_constraint("ck_runner_certificate_purpose", type_="check")
        batch.create_check_constraint(
            "ck_runner_certificate_purpose",
            "purpose IN ('preview_tunnel', 'secret_broker', 'billing_metering', 'runner_control')",
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            'CREATE POLICY "rls_runner_certificates_runner_control" '
            'ON public."saas_runner_certificates" FOR SELECT USING ('
            f"{_EXECUTOR} AND purpose = 'runner_control' AND {_PURPOSE} = 'runner_control' "
            f"AND fingerprint_sha256 = {_FINGERPRINT} AND {_CURRENT_CERTIFICATE})"
        )


def _drop_runner_control_certificate_purpose() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("LOCK TABLE public.saas_runner_certificates IN ACCESS EXCLUSIVE MODE")
        op.execute("ALTER TABLE public.saas_runner_certificates NO FORCE ROW LEVEL SECURITY")
    else:
        bind.exec_driver_sql(
            "UPDATE saas_runner_certificates SET updated_at = updated_at WHERE 1 = 0"
        )
    occupied = bind.execute(
        sa.text("SELECT 1 FROM saas_runner_certificates WHERE purpose = 'runner_control' LIMIT 1")
    ).first()
    if occupied is not None:
        if bind.dialect.name == "postgresql":
            op.execute("ALTER TABLE public.saas_runner_certificates FORCE ROW LEVEL SECURITY")
        raise RuntimeError(_RUNNER_CONTROL_DOWNGRADE_BLOCKED)
    if bind.dialect.name == "postgresql":
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_certificates_runner_control" '
            'ON public."saas_runner_certificates"'
        )
    with op.batch_alter_table("saas_runner_certificates") as batch:
        batch.drop_constraint("ck_runner_certificate_purpose", type_="check")
        batch.create_check_constraint(
            "ck_runner_certificate_purpose",
            "purpose IN ('preview_tunnel', 'secret_broker', 'billing_metering')",
        )
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE public.saas_runner_certificates FORCE ROW LEVEL SECURITY")


def upgrade() -> None:
    _require_pre_upgrade_dispatch_drain()
    _install_runner_control_certificate_purpose()
    op.create_index(
        "uq_execution_profile_active_scope",
        "saas_execution_profiles",
        ("tenant_id", "space_id", "project_id"),
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )
    with op.batch_alter_table("saas_run_dispatches") as batch:
        batch.add_column(sa.Column("execution_profile_id", sa.Uuid(), nullable=False))
        batch.add_column(sa.Column("execution_profile_hash", sa.String(64), nullable=False))
        batch.add_column(sa.Column("egress_policy_id", sa.Uuid(), nullable=False))
        batch.add_column(sa.Column("egress_policy_hash", sa.String(64), nullable=False))
        batch.add_column(
            sa.Column("recovery_quarantined_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("recovery_quarantine_reason", sa.String(128), nullable=True))
        batch.create_foreign_key(
            "fk_run_dispatch_execution_profile_scope",
            "saas_execution_profiles",
            ["execution_profile_id", "tenant_id", "space_id", "project_id"],
            ["id", "tenant_id", "space_id", "project_id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_run_dispatch_egress_policy_scope",
            "saas_egress_policies",
            ["egress_policy_id", "tenant_id", "space_id", "project_id"],
            ["id", "tenant_id", "space_id", "project_id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_run_dispatch_execution_profile_binding",
            "length(execution_profile_hash) = 64",
        )
        batch.create_check_constraint(
            "ck_run_dispatch_egress_policy_binding",
            "length(egress_policy_hash) = 64",
        )
        batch.create_check_constraint(
            "ck_run_dispatch_recovery_quarantine",
            "(recovery_quarantined_at IS NULL AND recovery_quarantine_reason IS NULL) OR "
            "(recovery_quarantined_at IS NOT NULL "
            "AND length(recovery_quarantine_reason) > 0)",
        )
    _install_postgresql_executor_profile_policies()
    _restore_postgresql_force_rls()


def downgrade() -> None:
    _require_pre_downgrade_dispatch_drain()
    _drop_runner_control_certificate_purpose()
    _drop_postgresql_executor_profile_policies()
    with op.batch_alter_table("saas_run_dispatches") as batch:
        batch.drop_constraint("ck_run_dispatch_recovery_quarantine", type_="check")
        batch.drop_constraint(
            "ck_run_dispatch_egress_policy_binding",
            type_="check",
        )
        batch.drop_constraint(
            "ck_run_dispatch_execution_profile_binding",
            type_="check",
        )
        batch.drop_constraint(
            "fk_run_dispatch_egress_policy_scope",
            type_="foreignkey",
        )
        batch.drop_constraint(
            "fk_run_dispatch_execution_profile_scope",
            type_="foreignkey",
        )
        batch.drop_column("egress_policy_hash")
        batch.drop_column("egress_policy_id")
        batch.drop_column("execution_profile_hash")
        batch.drop_column("execution_profile_id")
        batch.drop_column("recovery_quarantine_reason")
        batch.drop_column("recovery_quarantined_at")
    op.drop_index("uq_execution_profile_active_scope", table_name="saas_execution_profiles")
    _restore_postgresql_force_rls()
