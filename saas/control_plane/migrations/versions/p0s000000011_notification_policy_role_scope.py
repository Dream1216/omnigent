"""Scope notification source policies to their exact service roles.

Revision ID: p0s000000011
Revises: p0s000000010
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000011"
down_revision: str | None = "p0s000000010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SOURCE_ROLES = (
    "saas_approval_scheduler_audit",
    "saas_approval_scheduler_enterprise",
    "saas_approval_scheduler_privacy",
    "saas_approval_scheduler_support_customer",
    "saas_approval_scheduler_support_staff",
)
_TARGET_POLICY_ROLES = {
    (
        "saas_approval_work_items",
        "rls_approval_work_approval_scheduler_source",
    ): _SOURCE_ROLES,
    (
        "saas_notification_deliveries",
        "rls_saas_notification_deliveries_governance_insert",
    ): ("saas_platform",),
    (
        "saas_notification_deliveries",
        "rls_saas_notification_deliveries_bound_insert",
    ): tuple(
        sorted(
            (
                "saas_governance",
                "saas_notification_scheduler",
                "saas_platform_governance",
                *_SOURCE_ROLES,
            )
        )
    ),
    (
        "saas_notification_deliveries",
        "rls_saas_notification_deliveries_source_exact_read",
    ): _SOURCE_ROLES,
}
_PUBLIC = ("PUBLIC",)


def _policy_projection(table: str, policy: str) -> tuple[object, ...]:
    row = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT policy.oid::bigint AS oid, policy.polcmd AS command, "
                "policy.polpermissive AS permissive, "
                "pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) AS qualifier, "
                "pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid) AS with_check, "
                "ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' "
                "ELSE COALESCE(role.rolname, '<missing-role:' || role_oid::text || '>') END "
                "FROM pg_catalog.unnest(policy.polroles) AS role_oid "
                "LEFT JOIN pg_catalog.pg_roles AS role ON role.oid = role_oid "
                "ORDER BY 1) AS roles "
                "FROM pg_catalog.pg_policy AS policy "
                "JOIN pg_catalog.pg_class AS relation ON relation.oid = policy.polrelid "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                "AND policy.polname = :policy"
            ),
            {"table": table, "policy": policy},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise RuntimeError(f"P0S11 notification policy is missing: {table}.{policy}")
    return (
        int(row["oid"]),
        str(row["command"]),
        bool(row["permissive"]),
        row["qualifier"],
        row["with_check"],
        tuple(row["roles"]),
    )


def _transition_policy_roles(
    *,
    expected: dict[tuple[str, str], tuple[str, ...]],
    target: dict[tuple[str, str], tuple[str, ...]],
    phase: str,
) -> None:
    baselines: dict[tuple[str, str], tuple[object, ...]] = {}
    for key, expected_roles in expected.items():
        projection = _policy_projection(*key)
        if projection[-1] != tuple(sorted(expected_roles)):
            raise RuntimeError(f"P0S11 {phase} policy role projection drifted: {key[0]}.{key[1]}")
        baselines[key] = projection[:-1]

    for (table, policy), target_roles in target.items():
        op.execute(f'ALTER POLICY "{policy}" ON public."{table}" TO {", ".join(target_roles)}')

    for key, target_roles in target.items():
        projection = _policy_projection(*key)
        if projection[:-1] != baselines[key] or projection[-1] != tuple(sorted(target_roles)):
            raise RuntimeError(
                f"P0S11 {phase} policy identity projection drifted: {key[0]}.{key[1]}"
            )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    predecessor: dict[tuple[str, str], tuple[str, ...]] = dict.fromkeys(
        _TARGET_POLICY_ROLES, _PUBLIC
    )
    _transition_policy_roles(
        expected=predecessor,
        target=_TARGET_POLICY_ROLES,
        phase="upgrade",
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    predecessor: dict[tuple[str, str], tuple[str, ...]] = dict.fromkeys(
        _TARGET_POLICY_ROLES, _PUBLIC
    )
    _transition_policy_roles(
        expected=_TARGET_POLICY_ROLES,
        target=predecessor,
        phase="downgrade",
    )
