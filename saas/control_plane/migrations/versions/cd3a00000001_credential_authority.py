"""Keep per-user credential authority and durable Casdoor migration receipts."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "cd3a00000001"
down_revision = "cd2a00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_credential_migration_receipts"
_STATES = "'legacy', 'pending', 'imported', 'cutover', 'recovery_required', 'recovered', 'native'"
_AUTHORITY_STATE = (
    "(credential_owner = 'legacy' AND migration_state IN "
    "('legacy', 'pending', 'imported', 'recovered')) OR "
    "(credential_owner = 'casdoor' AND migration_state IN "
    "('native', 'cutover', 'recovery_required'))"
)
_IMMUTABLE = (
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


def _owner(table: str) -> str:
    return (
        "current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
        f"WHERE oid = 'public.{table}'::regclass))"
    )


def _hex64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


def _create_receipts() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        *[
            sa.Column(name, sa.String(size), nullable=False)
            for name, size in (
                ("batch_id", 128),
                ("issuer", 512),
                ("organization", 64),
                ("provider_subject", 512),
                ("provider_username", 128),
                ("source_password_sha256", 64),
                ("source_email_sha256", 64),
                ("policy_sha256", 64),
                ("idempotency_key", 64),
                ("request_hash", 64),
            )
        ],
        sa.Column("source_password_version", sa.Integer(), nullable=False),
        sa.Column("source_security_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("provider_snapshot_sha256", sa.String(64)),
        sa.Column(
            "identity_connection_id",
            sa.Uuid(),
            sa.ForeignKey("saas_identity_connections.id", ondelete="RESTRICT"),
        ),
        sa.Column("last_error_code", sa.String(128)),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("claim_token", sa.Uuid()),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        *[
            sa.Column(name, sa.DateTime(timezone=True))
            for name in ("imported_at", "completed_at", "recovered_at")
        ],
        sa.UniqueConstraint("idempotency_key"),
        sa.UniqueConstraint("batch_id", "user_id", name="uq_credential_migration_batch_user"),
        sa.CheckConstraint(
            "status IN ('pending', 'imported', 'completed', 'conflict', 'failed', 'recovered')",
            name="ck_credential_migration_status",
        ),
        sa.CheckConstraint(
            "source_password_version > 0 AND source_security_version > 0 "
            "AND attempt_count >= 0 AND version > 0",
            name="ck_credential_migration_versions",
        ),
        sa.CheckConstraint(
            "length(batch_id) > 0 AND length(issuer) > 0 AND length(organization) > 0 "
            "AND length(provider_subject) > 0 AND length(provider_username) > 0",
            name="ck_credential_migration_target",
        ),
        *[
            sa.CheckConstraint(_hex64(name), name="ck_credential_migration_" + name)
            for name in (
                "source_password_sha256",
                "source_email_sha256",
                "policy_sha256",
                "idempotency_key",
                "request_hash",
            )
        ],
        sa.CheckConstraint(
            "provider_snapshot_sha256 IS NULL OR (" + _hex64("provider_snapshot_sha256") + ")",
            name="ck_credential_migration_snapshot_sha256",
        ),
        sa.CheckConstraint(
            "(claim_token IS NULL AND lease_expires_at IS NULL) OR "
            "(claim_token IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND status IN ('pending', 'imported'))",
            name="ck_credential_migration_lease",
        ),
        sa.CheckConstraint(
            "status NOT IN ('imported', 'completed', 'recovered') OR "
            "(imported_at IS NOT NULL AND provider_snapshot_sha256 IS NOT NULL)",
            name="ck_credential_migration_import_receipt",
        ),
        sa.CheckConstraint(
            "status NOT IN ('completed', 'recovered') OR "
            "(completed_at IS NOT NULL AND identity_connection_id IS NOT NULL)",
            name="ck_credential_migration_completion",
        ),
        sa.CheckConstraint(
            "(status = 'recovered') = (recovered_at IS NOT NULL)",
            name="ck_credential_migration_recovery",
        ),
    )
    op.create_index(
        "uq_credential_migration_active_user",
        _TABLE,
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'imported')"),
        sqlite_where=sa.text("status IN ('pending', 'imported')"),
    )


def upgrade() -> None:
    bind = op.get_bind()
    with op.batch_alter_table("saas_global_users") as batch:
        batch.add_column(
            sa.Column("credential_owner", sa.String(16), nullable=False, server_default="legacy")
        )
        batch.add_column(
            sa.Column("migration_state", sa.String(32), nullable=False, server_default="legacy")
        )
        batch.create_check_constraint(
            "ck_user_credential_owner", "credential_owner IN ('legacy', 'casdoor')"
        )
        batch.create_check_constraint("ck_user_migration_state", f"migration_state IN ({_STATES})")
        batch.create_check_constraint("ck_user_credential_authority_state", _AUTHORITY_STATE)
    _create_receipts()
    if bind.dialect.name == "postgresql":
        for table in (
            "saas_global_users",
            "saas_identity_connections",
            "saas_password_credentials",
        ):
            op.execute(
                f"CREATE POLICY credential_backfill_select ON {table} "
                f"FOR SELECT USING ({_owner(table)})"
            )
        op.execute(
            "CREATE POLICY credential_backfill_update ON saas_global_users FOR UPDATE "
            f"USING ({_owner('saas_global_users')}) "
            f"WITH CHECK ({_owner('saas_global_users')})"
        )
    op.execute(
        "UPDATE saas_global_users SET credential_owner='casdoor', migration_state='native' "
        "WHERE EXISTS (SELECT 1 FROM saas_identity_connections identity "
        "WHERE identity.user_id=saas_global_users.id AND identity.provider='casdoor' "
        "AND identity.status='active') AND NOT EXISTS "
        "(SELECT 1 FROM saas_password_credentials password "
        "WHERE password.user_id=saas_global_users.id)"
    )
    if bind.dialect.name != "postgresql":
        return
    op.execute("DROP POLICY credential_backfill_update ON saas_global_users")
    for table in ("saas_global_users", "saas_identity_connections", "saas_password_credentials"):
        op.execute(f"DROP POLICY credential_backfill_select ON {table}")
    op.execute(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY")
    authority = "pg_has_role(current_user, 'saas_authenticator', 'member')"
    op.execute(
        f"CREATE POLICY rls_credential_migration_authenticator ON {_TABLE} "
        f"FOR ALL USING ({authority}) WITH CHECK ({authority})"
    )
    op.execute(
        f"CREATE POLICY rls_credential_migration_owner_read ON {_TABLE} "
        f"FOR SELECT USING ({_owner(_TABLE)})"
    )
    op.execute(
        "CREATE POLICY rls_credential_authority_owner_read ON saas_global_users FOR SELECT USING "
        f"({_owner('saas_global_users')} "
        "AND (credential_owner <> 'legacy' OR migration_state <> 'legacy'))"
    )
    changed = " OR ".join(f"NEW.{name} IS DISTINCT FROM OLD.{name}" for name in _IMMUTABLE)
    op.execute(f"""
        CREATE FUNCTION public.saas_guard_credential_migration_receipt() RETURNS trigger
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
        CREATE TRIGGER credential_migration_receipt_guard
        BEFORE UPDATE OR DELETE ON public.{_TABLE}
        FOR EACH ROW EXECUTE FUNCTION public.saas_guard_credential_migration_receipt();
    """)


def downgrade() -> None:
    bind = op.get_bind()
    retained = bind.execute(sa.text(f"SELECT 1 FROM {_TABLE} LIMIT 1")).first()
    authority = bind.execute(
        sa.text(
            "SELECT 1 FROM saas_global_users WHERE credential_owner <> 'legacy' "
            "OR migration_state <> 'legacy' LIMIT 1"
        )
    ).first()
    if retained is not None or authority is not None:
        raise RuntimeError(
            "retained credential authority requires application-only rollback "
            "with a matched identity recovery set"
        )
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP TRIGGER credential_migration_receipt_guard ON {_TABLE}")
        op.execute("DROP FUNCTION public.saas_guard_credential_migration_receipt()")
        op.execute("DROP POLICY rls_credential_authority_owner_read ON saas_global_users")
    op.drop_table(_TABLE)
    with op.batch_alter_table("saas_global_users") as batch:
        batch.drop_constraint("ck_user_credential_authority_state", type_="check")
        batch.drop_constraint("ck_user_migration_state", type_="check")
        batch.drop_constraint("ck_user_credential_owner", type_="check")
        batch.drop_column("migration_state")
        batch.drop_column("credential_owner")
