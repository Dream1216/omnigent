"""Add network registration policies and seal key-rotation invariants.

Revision ID: p0s000000006
Revises: p0s000000005
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000006"
down_revision: str | None = "p0s000000005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY_REVISION = "registration-rate-limit-v1"
_NETWORK_POLICIES = (
    ("registration.request", "network", 60, 900, 86400, 1_000_000),
    ("registration.resend", "network", 60, 900, 86400, 1_000_000),
    ("registration.verify", "network", 120, 900, 86400, 1_000_000),
)
_CONSUME_SIGNATURE = (
    "public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)"
)
_ROTATION_GUARD = """            IF (p_previous_key_id IS NOT NULL
                AND p_anchor_key_id <> p_previous_key_id)
               OR (p_previous_key_id IS NULL AND (
                    p_anchor_key_id <> p_active_key_id
                    OR p_write_key_id <> p_active_key_id
               )) THEN
                RAISE EXCEPTION 'registration rate-limit rotation phase rejected'
                    USING ERRCODE = '22023';
            END IF;

"""
_ROTATION_INSERTION_POINT = """            IF p_anchor_key_id = p_active_key_id THEN
"""


def _subject_kind_check(table: str, constraint: str, *, include_network: bool) -> None:
    kinds = "'email', 'registration', 'network'" if include_network else "'email', 'registration'"
    if op.get_bind().dialect.name == "sqlite":
        batch_context = op.batch_alter_table(table, recreate="always")
    else:
        batch_context = op.batch_alter_table(table)
    with batch_context as batch_op:
        batch_op.drop_constraint(constraint, type_="check")
        batch_op.create_check_constraint(constraint, f"subject_kind IN ({kinds})")


def _replace_consume_rotation_guard(*, install: bool) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    definition = bind.execute(
        sa.text("SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure(:signature))"),
        {"signature": _CONSUME_SIGNATURE},
    ).scalar_one()
    if install:
        if _ROTATION_GUARD in definition or definition.count(_ROTATION_INSERTION_POINT) != 1:
            raise RuntimeError("cannot install p0s000000006 rotation guard")
        definition = definition.replace(
            _ROTATION_INSERTION_POINT,
            _ROTATION_GUARD + _ROTATION_INSERTION_POINT,
            1,
        )
    else:
        if definition.count(_ROTATION_GUARD) != 1:
            raise RuntimeError("cannot restore p0s000000005 rotation guard contract")
        definition = definition.replace(_ROTATION_GUARD, "", 1)
    bind.exec_driver_sql(definition)


def _assert_downgrade_safe() -> None:
    bind = op.get_bind()
    is_postgresql = bind.dialect.name == "postgresql"
    if is_postgresql:
        op.execute(
            "LOCK TABLE public.saas_registration_rate_limit_policies, "
            "public.saas_registration_rate_limits IN ACCESS EXCLUSIVE MODE"
        )
        op.execute("ALTER TABLE public.saas_registration_rate_limits NO FORCE ROW LEVEL SECURITY")
    try:
        has_network_counters = (
            bind.execute(
                sa.text(
                    "SELECT 1 FROM saas_registration_rate_limits "
                    "WHERE subject_kind = 'network' LIMIT 1"
                )
            ).first()
            is not None
        )
        actual_network_policies = {
            tuple(row)
            for row in bind.execute(
                sa.text(
                    "SELECT action, subject_kind, limit_count, window_seconds, "
                    "retention_seconds, max_rows, current_rows, policy_revision "
                    "FROM saas_registration_rate_limit_policies "
                    "WHERE subject_kind = 'network'"
                )
            )
        }
    finally:
        if is_postgresql:
            op.execute("ALTER TABLE public.saas_registration_rate_limits FORCE ROW LEVEL SECURITY")
    expected_network_policies = {(*policy, 0, _POLICY_REVISION) for policy in _NETWORK_POLICIES}
    if has_network_counters:
        raise RuntimeError("cannot downgrade p0s000000006 with network rate-limit counters")
    if actual_network_policies != expected_network_policies:
        raise RuntimeError("cannot downgrade p0s000000006 with network policy drift")


def upgrade() -> None:
    _subject_kind_check(
        "saas_registration_rate_limit_policies",
        "ck_registration_rate_limit_policy_subject_kind",
        include_network=True,
    )
    _subject_kind_check(
        "saas_registration_rate_limits",
        "ck_registration_rate_limit_subject_kind",
        include_network=True,
    )
    policies = sa.table(
        "saas_registration_rate_limit_policies",
        sa.column("action", sa.String()),
        sa.column("subject_kind", sa.String()),
        sa.column("limit_count", sa.Integer()),
        sa.column("window_seconds", sa.Integer()),
        sa.column("retention_seconds", sa.Integer()),
        sa.column("max_rows", sa.Integer()),
        sa.column("current_rows", sa.Integer()),
        sa.column("policy_revision", sa.String()),
    )
    op.bulk_insert(
        policies,
        [
            {
                "action": action,
                "subject_kind": subject_kind,
                "limit_count": limit_count,
                "window_seconds": window_seconds,
                "retention_seconds": retention_seconds,
                "max_rows": max_rows,
                "current_rows": 0,
                "policy_revision": _POLICY_REVISION,
            }
            for (
                action,
                subject_kind,
                limit_count,
                window_seconds,
                retention_seconds,
                max_rows,
            ) in _NETWORK_POLICIES
        ],
    )
    _replace_consume_rotation_guard(install=True)


def downgrade() -> None:
    _assert_downgrade_safe()
    op.execute("DELETE FROM saas_registration_rate_limit_policies WHERE subject_kind = 'network'")
    _subject_kind_check(
        "saas_registration_rate_limits",
        "ck_registration_rate_limit_subject_kind",
        include_network=False,
    )
    _subject_kind_check(
        "saas_registration_rate_limit_policies",
        "ck_registration_rate_limit_policy_subject_kind",
        include_network=False,
    )
    _replace_consume_rotation_guard(install=False)
