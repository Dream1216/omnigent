"""Allow the direct table owner to maintain retained Runtime metadata.

Revision ID: p0s000000018
Revises: p0s000000017

This installs no service authority or metadata upgrade. The release maintenance
coordinator must independently verify its backup, write fence, installed runtime
and complete placement scope before changing any row.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "p0s000000018"
down_revision = "p0s000000017"
branch_labels = None
depends_on = None

POLICIES = (
    (
        "saas_runtime_placements",
        "rls_runtime_placement_maintenance_owner_update_v1",
        "UPDATE",
    ),
    (
        "saas_runtime_partitions",
        "rls_runtime_partition_maintenance_owner_update_v1",
        "UPDATE",
    ),
    (
        "saas_runtime_resource_bindings",
        "rls_runtime_binding_maintenance_owner_select_v1",
        "SELECT",
    ),
    (
        "saas_runtime_resource_bindings",
        "rls_runtime_binding_maintenance_owner_update_v1",
        "UPDATE",
    ),
)


def _owner_expression(table: str) -> str:
    return (
        "current_user = pg_catalog.pg_get_userbyid((SELECT relation.relowner "
        "FROM pg_catalog.pg_class AS relation "
        f"WHERE relation.oid = 'public.{table}'::regclass))"
    )


def _preflight() -> None:
    bind = op.get_bind()
    for table in dict.fromkeys(table for table, _policy, _command in POLICIES):
        owned_and_forced = bind.execute(
            sa.text(
                "SELECT relation.relkind = 'r' AND relation.relrowsecurity "
                "AND relation.relforcerowsecurity AND relation.relowner = "
                "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user) "
                "FROM pg_catalog.pg_class AS relation "
                "WHERE relation.oid = pg_catalog.to_regclass(:relation)"
            ),
            {"relation": "public." + table},
        ).scalar_one_or_none()
        if owned_and_forced is not True:
            raise RuntimeError("P18 requires the original direct owner and FORCE RLS")
    for table, policy, _command in POLICIES:
        exists = bind.execute(
            sa.text(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_policy "
                "WHERE polrelid = pg_catalog.to_regclass(:relation) AND polname = :policy)"
            ),
            {"relation": "public." + table, "policy": policy},
        ).scalar_one()
        if exists:
            raise RuntimeError("P18 maintenance policy already exists or has drifted")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    _preflight()
    for table, policy, command in POLICIES:
        expression = _owner_expression(table)
        with_check = f" WITH CHECK ({expression})" if command == "UPDATE" else ""
        op.execute(
            f'CREATE POLICY "{policy}" ON public."{table}" '
            f"FOR {command} TO PUBLIC USING ({expression}){with_check}"
        )


def downgrade() -> None:
    raise RuntimeError(
        "P18 downgrade requires reviewed runtime-maintenance inverse; "
        "never remove policy contracts implicitly"
    )
