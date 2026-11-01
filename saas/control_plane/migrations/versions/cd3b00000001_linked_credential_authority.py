"""Distinguish existing verified identity cutover from prehashed user import."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "cd3b00000001"
down_revision = "cd3a00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_credential_migration_receipts"
_PREDECESSOR_IMMUTABLE = (
    "id",
    "user_id",
    "batch_id",
    "issuer",
    "organization",
    "provider_subject",
    "provider_username",
    "source_password_version",
    "source_security_version",
    "source_password_sha256",
    "source_email_sha256",
    "policy_sha256",
    "idempotency_key",
    "request_hash",
    "created_at",
)


def _guard(*, include_mode: bool) -> None:
    columns = (*_PREDECESSOR_IMMUTABLE, "mode") if include_mode else _PREDECESSOR_IMMUTABLE
    changed = " OR ".join(f"NEW.{name} IS DISTINCT FROM OLD.{name}" for name in columns)
    if include_mode:
        changed += (
            " OR (OLD.mode='existing_link' AND (NEW.identity_connection_id "
            "IS DISTINCT FROM OLD.identity_connection_id OR NEW.provider_snapshot_sha256 "
            "IS DISTINCT FROM OLD.provider_snapshot_sha256))"
        )
    # Keep the predecessor function body byte-for-byte when removing this
    # expansion; source catalog admission includes its exact prosrc.
    op.execute(f"""
        CREATE OR REPLACE FUNCTION public.saas_guard_credential_migration_receipt() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $guard$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'credential migration evidence is immutable';
            END IF;
            IF {changed} OR OLD.status IN ('conflict', 'failed', 'recovered') THEN
                RAISE EXCEPTION 'credential migration evidence is immutable';
            END IF;
            IF OLD.status='completed' AND (
                NEW.status<>'recovered' OR NEW.recovered_at IS NULL OR
                NEW.provider_snapshot_sha256 IS DISTINCT FROM OLD.provider_snapshot_sha256 OR
                NEW.identity_connection_id IS DISTINCT FROM OLD.identity_connection_id OR
                NEW.imported_at IS DISTINCT FROM OLD.imported_at OR
                NEW.completed_at IS DISTINCT FROM OLD.completed_at OR
                NEW.attempt_count IS DISTINCT FROM OLD.attempt_count OR
                NEW.claim_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
                NEW.last_error_code IS NOT NULL) THEN
                RAISE EXCEPTION 'completed credential migration evidence is immutable';
            END IF;
            RETURN NEW;
        END
        $guard$;
        REVOKE ALL ON FUNCTION public.saas_guard_credential_migration_receipt() FROM PUBLIC;
    """)


def upgrade() -> None:
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(
            sa.Column("mode", sa.String(32), nullable=False, server_default="hash_import")
        )
        batch.create_check_constraint(
            "ck_credential_migration_mode", "mode IN ('hash_import', 'existing_link')"
        )
        batch.create_check_constraint(
            "ck_credential_migration_link_proof",
            "mode <> 'existing_link' OR (identity_connection_id IS NOT NULL "
            "AND provider_snapshot_sha256 IS NOT NULL)",
        )
    op.create_index("ix_credential_migration_subject", _TABLE, ["issuer", "provider_subject"])
    if op.get_bind().dialect.name == "postgresql":
        _guard(include_mode=True)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {_TABLE} WHERE mode<>'hash_import' LIMIT 1")).first():
        raise RuntimeError("retained existing identity cutover requires application-only rollback")
    if bind.dialect.name == "postgresql":
        _guard(include_mode=False)
    op.drop_index("ix_credential_migration_subject", table_name=_TABLE)
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_constraint("ck_credential_migration_link_proof", type_="check")
        batch.drop_constraint("ck_credential_migration_mode", type_="check")
        batch.drop_column("mode")
