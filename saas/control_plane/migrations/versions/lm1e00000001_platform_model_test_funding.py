"""Give platform-funded model verification an explicit, keyless budget scope.

Revision ID: lm1e00000001
Revises: lm1d00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision: str = "lm1e00000001"
down_revision: str | None = "lm1d00000001"
branch_labels: str | None = None
depends_on: str | None = None

_POLICY = "saas_model_test_funding_policies"
_BUDGET = "saas_model_provider_budget_reservations"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"


def _assignment(*roles: str) -> str:
    values = ", ".join(f"'{role}'" for role in roles)
    return (
        "(pg_has_role(current_user, 'saas_platform_app', 'member') "
        f"AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} AND assignment.role IN ({values}) "
        "AND assignment.status = 'active' AND (assignment.expires_at IS NULL "
        "OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def upgrade() -> None:
    op.create_table(
        _POLICY,
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("monthly_budget_microusd", sa.BigInteger(), nullable=False),
        sa.Column("daily_test_budget_microusd", sa.BigInteger(), nullable=False),
        sa.Column("daily_test_token_limit", sa.BigInteger(), nullable=False),
        sa.Column("max_test_microusd", sa.BigInteger(), nullable=False),
        sa.Column("max_test_tokens", sa.Integer(), nullable=False),
        sa.Column("daily_test_attempt_limit", sa.Integer(), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("provider_id", "version"),
        sa.ForeignKeyConstraint(
            ["actor_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "provider_id = 'deepseek' AND version > 0", name="ck_model_test_policy_identity"
        ),
        sa.CheckConstraint(
            "monthly_budget_microusd BETWEEN 1 AND 1000000000000000 "
            "AND daily_test_budget_microusd BETWEEN 1 AND monthly_budget_microusd "
            "AND max_test_microusd BETWEEN 1 AND daily_test_budget_microusd "
            "AND daily_test_token_limit BETWEEN 1 AND 1000000000 "
            "AND max_test_tokens BETWEEN 1 AND 2048 "
            "AND max_test_tokens <= daily_test_token_limit "
            "AND daily_test_attempt_limit BETWEEN 1 AND 1000",
            name="ck_model_test_policy_limits",
        ),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_model_test_policy_hash"),
    )
    with op.batch_alter_table(_BUDGET) as batch:
        batch.alter_column("tenant_id", existing_type=sa.Uuid(), nullable=True)
        batch.alter_column("run_id", existing_type=sa.Uuid(), nullable=True)
        batch.add_column(
            sa.Column("purpose", sa.String(16), nullable=False, server_default="tenant_run")
        )
        batch.add_column(sa.Column("test_operation_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("test_actor_principal_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("test_policy_version", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("test_configuration_sha256", sa.String(64), nullable=True))
        batch.create_foreign_key(
            "fk_model_budget_test_actor",
            "saas_platform_staff_principals",
            ["test_actor_principal_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_model_budget_test_policy",
            _POLICY,
            ["provider_id", "test_policy_version"],
            ["provider_id", "version"],
            ondelete="RESTRICT",
        )
        batch.create_unique_constraint("uq_model_budget_test_operation", ["test_operation_id"])
        batch.create_check_constraint(
            "ck_model_budget_funding_scope",
            "(purpose = 'tenant_run' AND tenant_id IS NOT NULL AND run_id IS NOT NULL "
            "AND test_operation_id IS NULL AND test_actor_principal_id IS NULL "
            "AND test_policy_version IS NULL AND test_configuration_sha256 IS NULL) OR "
            "(purpose = 'platform_test' AND tenant_id IS NULL AND run_id IS NULL "
            "AND test_operation_id IS NOT NULL AND test_actor_principal_id IS NOT NULL "
            "AND test_policy_version IS NOT NULL AND test_configuration_sha256 IS NOT NULL "
            "AND test_policy_version > 0 AND " + _hex64("test_configuration_sha256") + ")",
        )
    op.create_index("ix_model_budget_test_day", _BUDGET, ["provider_id", "purpose", "usage_date"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"ALTER TABLE {_POLICY} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {_POLICY} FORCE ROW LEVEL SECURITY")
        read = _assignment("platform_operator", "platform_security_auditor")
        write = _assignment("platform_operator")
        op.execute(
            f"CREATE POLICY rls_model_test_funding_read ON {_POLICY} "
            f"FOR SELECT TO saas_platform_app USING ({read})"
        )
        op.execute(
            f"CREATE POLICY rls_model_test_funding_insert ON {_POLICY} "
            f"FOR INSERT TO saas_platform_app WITH CHECK ({write} "
            f"AND actor_principal_id = {_PRINCIPAL})"
        )
        op.execute(
            f"CREATE POLICY rls_model_test_funding_billing ON {_POLICY} "
            "FOR SELECT TO saas_billing USING (true)"
        )
        op.execute(
            f"CREATE POLICY rls_model_test_funding_recovery ON {_POLICY} "
            "FOR SELECT TO saas_platform, saas_platform_governance USING (true)"
        )
        op.execute(f"GRANT SELECT, INSERT ON {_POLICY} TO saas_platform_app")
        op.execute(
            f"GRANT SELECT ON {_POLICY} TO saas_billing, saas_platform, saas_platform_governance"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_POLICY}, {_BUDGET} IN ACCESS EXCLUSIVE MODE")
        for table in (_POLICY, _BUDGET):
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    if bind.execute(
        sa.text(
            f"SELECT EXISTS (SELECT 1 FROM {_POLICY}) OR EXISTS "
            f"(SELECT 1 FROM {_BUDGET} WHERE purpose <> 'tenant_run')"
        )
    ).scalar_one():
        raise RuntimeError("cannot remove retained platform test funding evidence")
    if bind.dialect.name == "postgresql":
        for table in (_POLICY, _BUDGET):
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.drop_index("ix_model_budget_test_day", table_name=_BUDGET)
    with op.batch_alter_table(_BUDGET) as batch:
        batch.drop_constraint("ck_model_budget_funding_scope", type_="check")
        batch.drop_constraint("uq_model_budget_test_operation", type_="unique")
        batch.drop_constraint("fk_model_budget_test_policy", type_="foreignkey")
        batch.drop_constraint("fk_model_budget_test_actor", type_="foreignkey")
        for column in (
            "test_configuration_sha256",
            "test_policy_version",
            "test_actor_principal_id",
            "test_operation_id",
            "purpose",
        ):
            batch.drop_column(column)
        batch.alter_column("tenant_id", existing_type=sa.Uuid(), nullable=False)
        batch.alter_column("run_id", existing_type=sa.Uuid(), nullable=False)
    op.drop_table(_POLICY)
