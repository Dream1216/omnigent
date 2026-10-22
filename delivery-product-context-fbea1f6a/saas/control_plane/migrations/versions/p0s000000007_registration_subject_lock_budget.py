"""Give same-subject registration serialization an independent lock budget.

Revision ID: p0s000000007
Revises: p0s000000006
"""

from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000007"
down_revision: str | None = "p0s000000006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONSUME_SIGNATURE = (
    "public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)"
)
_ROTATION_GUARD = "registration rate-limit rotation phase rejected"
_P0S6_PROSRC_SHA256 = "84edaf917bdde5521267880561cb83d9b6099530dc8d76b3d07d26eb32867a8b"
_P0S7_PROSRC_SHA256 = "8c21f811324aa7ebceae27b159369502ad24ae6aa9cc1e12c6e38070a8119112"
_LEGACY_SUBJECT_LOCK = """            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended(
                    'registration-rate-limit|' || p_action || '|' || p_subject_kind || '|'
                    || p_anchor_key_id || '|' || v_anchor_hmac,
                    0
                )
            );
"""
_BUDGETED_SUBJECT_LOCK = """            -- Keep policy/capacity locks at 250ms, but give healthy
            -- same-subject serialization its own bounded queue budget.  A single
            -- function-wide 250ms budget misclassifies expected quota contention
            -- as authority loss; exceeding two seconds still fails closed.
            PERFORM pg_catalog.set_config('lock_timeout', '2s', true);
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended(
                    'registration-rate-limit|' || p_action || '|' || p_subject_kind || '|'
                    || p_anchor_key_id || '|' || v_anchor_hmac,
                    0
                )
            );
            PERFORM pg_catalog.set_config('lock_timeout', '250ms', true);
            v_now := pg_catalog.clock_timestamp();
"""


def _replace_subject_lock(*, install: bool) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    contract = bind.execute(
        sa.text(
            """
            SELECT procedure.prosrc,
                   pg_catalog.pg_get_functiondef(procedure.oid)
            FROM pg_catalog.pg_proc AS procedure
            WHERE procedure.oid = pg_catalog.to_regprocedure(:signature)
            """
        ),
        {"signature": _CONSUME_SIGNATURE},
    ).one()
    source, definition = contract
    observed_hash = sha256(source.strip(" \n\r\t").encode("utf-8")).hexdigest()
    expected_hash = _P0S6_PROSRC_SHA256 if install else _P0S7_PROSRC_SHA256
    if observed_hash != expected_hash:
        raise RuntimeError(
            "cannot change registration rate-limit function with unexpected "
            f"contract hash {observed_hash}"
        )
    if _ROTATION_GUARD not in definition:
        raise RuntimeError("cannot change p0s000000007 without the p0s000000006 contract")
    if install:
        if _BUDGETED_SUBJECT_LOCK in definition or definition.count(_LEGACY_SUBJECT_LOCK) != 1:
            raise RuntimeError("cannot install p0s000000007 subject lock budget")
        definition = definition.replace(
            _LEGACY_SUBJECT_LOCK,
            _BUDGETED_SUBJECT_LOCK,
            1,
        )
    else:
        if definition.count(_BUDGETED_SUBJECT_LOCK) != 1:
            raise RuntimeError("cannot restore p0s000000006 subject lock contract")
        definition = definition.replace(
            _BUDGETED_SUBJECT_LOCK,
            _LEGACY_SUBJECT_LOCK,
            1,
        )
    bind.exec_driver_sql(definition)


def upgrade() -> None:
    _replace_subject_lock(install=True)


def downgrade() -> None:
    _replace_subject_lock(install=False)
