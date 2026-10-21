"""Store opaque model ciphertext in a byte-bounded, versioned binary envelope.

Revision ID: lm2p00000001
Revises: lm2o00000001

Deploy the schema before the matching application with model writes stopped.
No provider calls or re-encryption occur. A retained oversized or malformed
value refuses the transaction; it is never truncated or silently repaired.
Old binaries cannot read this representation: disable model admission before
rollback, convert the schema back, then start the old model consumers.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2p00000001"
down_revision = "lm2o00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_model_credential_versions"
_COLUMN = "api_key_ciphertext"
_BOUND = "ck_model_credential_ciphertext"
_VALIDATION = "ck_model_secret_storage_downgrade_validation"
_PREFIX = b"OGSM\x01\x01\x01"


def _sqlite_transaction() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        raise RuntimeError("model secret migration requires PostgreSQL or SQLite")
    # SQLite's legacy driver otherwise starts no transaction before batch DDL.
    if getattr(bind.connection.driver_connection, "in_transaction", True) is False:
        bind.exec_driver_sql("BEGIN")


def _sqlite_rewrite(*, to_binary: bool) -> None:
    table = sa.table(_TABLE, sa.column("id"), sa.column(_COLUMN))
    cursor = None
    while True:
        query = sa.select(table.c.id, table.c[_COLUMN]).order_by(table.c.id).limit(256)
        if cursor is not None:
            query = query.where(table.c.id > cursor)
        rows = op.get_bind().execute(query).all()
        if not rows:
            return
        for identifier, value in rows:
            if not isinstance(value, bytes):
                raise RuntimeError("model secret storage migration refused")
            if to_binary:
                if not 0 < len(value) <= 16376:
                    raise RuntimeError("model secret storage exceeds byte cap")
                payload = value
            else:
                if not 7 < len(value) <= 16383 or not value.startswith(_PREFIX):
                    raise RuntimeError("model secret storage cannot be downgraded")
                payload = value[7:]
            try:
                text = payload.decode("utf-8")
            except UnicodeError:
                raise RuntimeError("model secret storage cannot be downgraded") from None
            updated = op.get_bind().execute(
                table.update()
                .where(table.c.id == identifier)
                .values(**{_COLUMN: _PREFIX + payload if to_binary else text})
            )
            if updated.rowcount != 1:
                raise RuntimeError("model secret storage migration refused")
            cursor = identifier


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.drop_constraint(_BOUND, _TABLE, type_="check")
        op.alter_column(
            _TABLE,
            _COLUMN,
            existing_type=sa.Text(),
            type_=sa.LargeBinary(16383),
            existing_nullable=False,
            postgresql_using=(f"decode('{_PREFIX.hex()}','hex') || convert_to({_COLUMN},'UTF8')"),
        )
        op.create_check_constraint(_BOUND, _TABLE, f"length({_COLUMN}) BETWEEN 8 AND 16383")
    else:
        _sqlite_transaction()
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_constraint(_BOUND, type_="check")
            batch.alter_column(
                _COLUMN,
                existing_type=sa.Text(),
                type_=sa.LargeBinary(16383),
                existing_nullable=False,
            )
        _sqlite_rewrite(to_binary=True)
        with op.batch_alter_table(_TABLE) as batch:
            batch.create_check_constraint(_BOUND, f"length({_COLUMN}) BETWEEN 8 AND 16383")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.create_check_constraint(
            _VALIDATION,
            _TABLE,
            f"length({_COLUMN}) BETWEEN 8 AND 16383 AND "
            f"substring({_COLUMN} from 1 for 7)=decode('{_PREFIX.hex()}','hex')",
        )
        op.drop_constraint(_VALIDATION, _TABLE, type_="check")
        op.drop_constraint(_BOUND, _TABLE, type_="check")
        op.alter_column(
            _TABLE,
            _COLUMN,
            existing_type=sa.LargeBinary(16383),
            type_=sa.Text(),
            existing_nullable=False,
            postgresql_using=f"convert_from(substring({_COLUMN} from 8),'UTF8')",
        )
        op.create_check_constraint(_BOUND, _TABLE, f"length({_COLUMN}) > 0")
    else:
        _sqlite_transaction()
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_constraint(_BOUND, type_="check")
        _sqlite_rewrite(to_binary=False)
        with op.batch_alter_table(_TABLE) as batch:
            batch.alter_column(
                _COLUMN,
                existing_type=sa.LargeBinary(16383),
                type_=sa.Text(),
                existing_nullable=False,
            )
            batch.create_check_constraint(_BOUND, f"length({_COLUMN}) > 0")
