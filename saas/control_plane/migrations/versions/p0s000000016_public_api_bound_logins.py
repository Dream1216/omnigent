"""Apply exact machine credential RLS to bound service logins.

Revision ID: p0s000000016
Revises: p0s000000015
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000016"
down_revision: str | None = "p0s000000015"
branch_labels: str | None = None
depends_on: str | None = None

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
_POLICIES = (
    *(
        (table, f"rls_{table}_{suffix}")
        for table in _EXECUTION_TABLES
        for suffix in ("scope", "public_api_exact")
    ),
    ("saas_public_api_mutation_receipts", "rls_public_api_mutation_receipts_exact"),
    ("saas_public_api_rate_limits", "rls_public_api_rate_limits_exact"),
    ("saas_service_accounts", "rls_service_accounts_public_api_exact"),
    ("saas_api_credentials", "rls_api_credentials_public_api_exact"),
    ("saas_tenant_memberships", "rls_tenant_memberships_public_api_hidden"),
    ("saas_space_memberships", "rls_space_memberships_public_api_hidden"),
)
_EXACT_BASE_NAME = "CURRENT_USER = 'saas_public_api'::name"
_INHERITED_AUTHORITY = "pg_has_role(CURRENT_USER, 'saas_public_api'::name, 'USAGE'::text)"


def _replace_authority(old: str, new: str) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    quote = bind.dialect.identifier_preparer.quote
    for table, policy in _POLICIES:
        row = (
            bind.execute(
                sa.text(
                    "SELECT pg_get_expr(policy.polqual, policy.polrelid) AS qualifier, "
                    "pg_get_expr(policy.polwithcheck, policy.polrelid) AS with_check, "
                    "relation.relrowsecurity, relation.relforcerowsecurity "
                    "FROM pg_policy policy JOIN pg_class relation "
                    "ON relation.oid = policy.polrelid "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                    "AND policy.polname = :policy"
                ),
                {"table": table, "policy": policy},
            )
            .mappings()
            .one()
        )
        if not row["relrowsecurity"] or not row["relforcerowsecurity"]:
            raise RuntimeError("Public API policy table must retain FORCE RLS")
        clauses = []
        for field, keyword in (("qualifier", "USING"), ("with_check", "WITH CHECK")):
            expression = row[field]
            if expression is None:
                continue
            if old not in expression:
                raise RuntimeError(f"Unexpected public API authority predicate: {table}.{policy}")
            clauses.append(f"{keyword} ({expression.replace(old, new)})")
        if not clauses:
            raise RuntimeError("Public API policy has no authority predicate")
        bind.exec_driver_sql(
            f"ALTER POLICY {quote(policy)} ON public.{quote(table)} " + " ".join(clauses)
        )


def upgrade() -> None:
    _replace_authority(_EXACT_BASE_NAME, _INHERITED_AUTHORITY)


def downgrade() -> None:
    _replace_authority(_INHERITED_AUTHORITY, _EXACT_BASE_NAME)
