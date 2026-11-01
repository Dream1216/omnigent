"""Persist provider phone ownership without inferring proof or merging identities."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "cd4b00000001"
down_revision = "cd4a00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_identity_connections"


def _e164() -> str:
    remainder = "substr(phone_e164, 2)"
    for digit in "0123456789":
        remainder = f"replace({remainder}, '{digit}', '')"
    return (
        "phone_e164 IS NULL OR (length(phone_e164) BETWEEN 3 AND 16 AND "
        "substr(phone_e164, 1, 1) = '+' AND substr(phone_e164, 2, 1) BETWEEN '1' AND '9' "
        f"AND {remainder} = '')"
    )


def upgrade() -> None:
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(sa.Column("phone_e164", sa.String(16), nullable=True))
        batch.add_column(
            sa.Column("phone_verified", sa.Boolean(), server_default=sa.false(), nullable=False)
        )
        batch.create_check_constraint("ck_identity_phone_e164", _e164())
        batch.create_check_constraint(
            "ck_identity_phone_proof", "NOT phone_verified OR phone_e164 IS NOT NULL"
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            f"CREATE POLICY rls_identity_phone_privacy_erasure ON {_TABLE} "
            "AS RESTRICTIVE FOR UPDATE TO saas_privacy_executor "
            "WITH CHECK (phone_e164 IS NULL AND NOT phone_verified)"
        )


def downgrade() -> None:
    connection = op.get_bind()
    postgres = connection.dialect.name == "postgresql"
    if postgres:
        op.execute(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.execute(
            f"CREATE POLICY rls_phone_rollback_owner_read ON {_TABLE} FOR SELECT USING "
            "(current_user=pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
            f"WHERE oid='public.{_TABLE}'::regclass)))"
        )
    try:
        retained = connection.execute(
            sa.text(
                f"SELECT 1 FROM {_TABLE} WHERE phone_e164 IS NOT NULL OR phone_verified LIMIT 1"
            )
        ).first()
    finally:
        if postgres:
            op.execute(f"DROP POLICY rls_phone_rollback_owner_read ON {_TABLE}")
    if retained:
        raise RuntimeError("retained phone ownership requires application-only rollback")
    if postgres:
        op.execute(f"DROP POLICY rls_identity_phone_privacy_erasure ON {_TABLE}")
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_constraint("ck_identity_phone_proof", type_="check")
        batch.drop_constraint("ck_identity_phone_e164", type_="check")
        batch.drop_column("phone_verified")
        batch.drop_column("phone_e164")
