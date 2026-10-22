"""Create durable Runner certificate rotation and revocation authority.

Revision ID: p4d000000001
Revises: p4c000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p4d000000001"
down_revision: str | None = "p4c000000001"
branch_labels: str | None = None
depends_on: str | None = None

_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_SECRET_BROKER = "pg_has_role(current_user, 'saas_secret_broker', 'member')"
_PREVIEW_GATEWAY = "pg_has_role(current_user, 'saas_preview_gateway', 'member')"
_FINGERPRINT = "NULLIF(current_setting('app.presented_certificate_fingerprint', true), '')"
_PURPOSE = "NULLIF(current_setting('app.presented_certificate_purpose', true), '')"
_CURRENT_CERTIFICATE = (
    "certificate_not_before <= CURRENT_TIMESTAMP "
    "AND certificate_not_after > CURRENT_TIMESTAMP "
    "AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP))"
)


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.create_table(
        "saas_runner_certificates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("spki_sha256", sa.String(length=64), nullable=False),
        sa.Column("serial_hex", sa.String(length=64), nullable=False),
        sa.Column("spiffe_id", sa.String(length=200), nullable=False),
        sa.Column("trust_bundle_version", sa.String(length=64), nullable=False),
        sa.Column("rotation_generation", sa.BigInteger(), nullable=False),
        sa.Column("certificate_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("certificate_not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retire_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "purpose IN ('preview_tunnel', 'secret_broker')",
            name="ck_runner_certificate_purpose",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'retiring', 'revoked')",
            name="ck_runner_certificate_status",
        ),
        sa.CheckConstraint(
            "runner_connection_generation > 0",
            name="ck_runner_certificate_connection_generation",
        ),
        sa.CheckConstraint("rotation_generation > 0", name="ck_runner_certificate_rotation"),
        sa.CheckConstraint(
            "length(fingerprint_sha256) = 64", name="ck_runner_certificate_fingerprint"
        ),
        sa.CheckConstraint("length(spki_sha256) = 64", name="ck_runner_certificate_spki"),
        sa.CheckConstraint(
            "length(serial_hex) > 0 AND length(serial_hex) <= 64",
            name="ck_runner_certificate_serial",
        ),
        sa.CheckConstraint("length(spiffe_id) > 0", name="ck_runner_certificate_spiffe"),
        sa.CheckConstraint(
            "length(trust_bundle_version) > 0", name="ck_runner_certificate_trust_bundle"
        ),
        sa.CheckConstraint(
            "certificate_not_after > certificate_not_before",
            name="ck_runner_certificate_validity",
        ),
        sa.CheckConstraint(
            "(status = 'active' AND retire_at IS NULL AND revoked_at IS NULL "
            "AND revocation_reason IS NULL) OR "
            "(status = 'retiring' AND retire_at IS NOT NULL AND retire_at >= activated_at "
            "AND revoked_at IS NULL "
            "AND revocation_reason IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= activated_at "
            "AND length(revocation_reason) > 0)",
            name="ck_runner_certificate_lifecycle",
        ),
        sa.ForeignKeyConstraint(
            ("runner_id",),
            ("saas_runner_registrations.id",),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint_sha256"),
        sa.UniqueConstraint(
            "runner_id",
            "purpose",
            "rotation_generation",
            name="uq_runner_certificate_rotation",
        ),
    )
    op.create_index(
        "ix_runner_certificate_authorize",
        "saas_runner_certificates",
        ("fingerprint_sha256", "purpose", "status"),
    )
    op.create_index(
        "ix_runner_certificate_rotation",
        "saas_runner_certificates",
        ("runner_id", "purpose", "rotation_generation"),
    )
    op.create_index(
        "uq_runner_certificate_active",
        "saas_runner_certificates",
        ("runner_id", "purpose"),
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
        sqlite_where=sa.text("status = 'active'"),
    )
    if not _is_postgresql():
        return

    op.execute('ALTER TABLE "saas_runner_certificates" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_runner_certificates" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY "rls_runner_certificates_platform" '
        'ON "saas_runner_certificates" FOR ALL '
        f"USING ({_PLATFORM}) WITH CHECK ({_PLATFORM})"
    )
    op.execute(
        'CREATE POLICY "rls_runner_certificates_secret_broker" '
        'ON "saas_runner_certificates" FOR SELECT USING ('
        f"{_SECRET_BROKER} AND purpose = 'secret_broker' AND {_PURPOSE} = 'secret_broker' "
        f"AND fingerprint_sha256 = {_FINGERPRINT} AND {_CURRENT_CERTIFICATE})"
    )
    op.execute(
        'CREATE POLICY "rls_runner_certificates_preview_gateway" '
        'ON "saas_runner_certificates" FOR SELECT USING ('
        f"{_PREVIEW_GATEWAY} AND purpose = 'preview_tunnel' AND {_PURPOSE} = 'preview_tunnel' "
        f"AND fingerprint_sha256 = {_FINGERPRINT} AND {_CURRENT_CERTIFICATE})"
    )
    op.execute(
        'CREATE POLICY "rls_runner_registrations_certificate_service" '
        'ON "saas_runner_registrations" FOR SELECT USING ('
        "EXISTS (SELECT 1 FROM saas_runner_certificates certificate "
        "WHERE certificate.runner_id = saas_runner_registrations.id AND "
        "certificate.runner_connection_generation = "
        "saas_runner_registrations.connection_generation AND "
        f"certificate.fingerprint_sha256 = {_FINGERPRINT} AND ("
        f"({_SECRET_BROKER} AND certificate.purpose = 'secret_broker' "
        f"AND {_PURPOSE} = 'secret_broker') OR "
        f"({_PREVIEW_GATEWAY} AND certificate.purpose = 'preview_tunnel' "
        f"AND {_PURPOSE} = 'preview_tunnel'))))"
    )
    op.execute(
        """
        CREATE FUNCTION saas_guard_runner_certificate_lifecycle()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(
                NEW.id, NEW.runner_id, NEW.runner_connection_generation, NEW.purpose,
                NEW.fingerprint_sha256, NEW.spki_sha256, NEW.serial_hex, NEW.spiffe_id,
                NEW.trust_bundle_version, NEW.rotation_generation,
                NEW.certificate_not_before, NEW.certificate_not_after,
                NEW.activated_at, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.id, OLD.runner_id, OLD.runner_connection_generation, OLD.purpose,
                OLD.fingerprint_sha256, OLD.spki_sha256, OLD.serial_hex, OLD.spiffe_id,
                OLD.trust_bundle_version, OLD.rotation_generation,
                OLD.certificate_not_before, OLD.certificate_not_after,
                OLD.activated_at, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'Runner certificate authority fields are immutable';
            END IF;
            IF NOT (
                ROW(OLD.status, OLD.retire_at, OLD.revoked_at, OLD.revocation_reason)
                    IS NOT DISTINCT FROM
                ROW(NEW.status, NEW.retire_at, NEW.revoked_at, NEW.revocation_reason)
                OR (
                    OLD.status = 'active' AND NEW.status = 'retiring'
                    AND OLD.retire_at IS NULL AND NEW.retire_at IS NOT NULL
                    AND NEW.revoked_at IS NULL AND NEW.revocation_reason IS NULL
                )
                OR (
                    OLD.status = 'retiring' AND NEW.status = 'retiring'
                    AND NEW.retire_at IS NOT NULL AND NEW.retire_at <= OLD.retire_at
                    AND NEW.revoked_at IS NULL AND NEW.revocation_reason IS NULL
                )
                OR (
                    OLD.status IN ('active', 'retiring') AND NEW.status = 'revoked'
                    AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
                    AND NEW.revocation_reason IS NOT NULL
                )
            ) THEN
                RAISE EXCEPTION 'Runner certificate lifecycle is monotonic';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_guard_runner_certificate_lifecycle
        BEFORE UPDATE ON saas_runner_certificates
        FOR EACH ROW EXECUTE FUNCTION saas_guard_runner_certificate_lifecycle()
        """
    )
    op.execute(
        """
        CREATE FUNCTION saas_reject_runner_certificate_delete()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Runner certificate records are append-only';
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_reject_runner_certificate_delete
        BEFORE DELETE ON saas_runner_certificates
        FOR EACH ROW EXECUTE FUNCTION saas_reject_runner_certificate_delete()
        """
    )


def downgrade() -> None:
    if _is_postgresql():
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_registrations_certificate_service" '
            'ON "saas_runner_registrations"'
        )
        op.execute(
            "DROP TRIGGER IF EXISTS trg_reject_runner_certificate_delete "
            "ON saas_runner_certificates"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_reject_runner_certificate_delete()")
        op.execute(
            "DROP TRIGGER IF EXISTS trg_guard_runner_certificate_lifecycle "
            "ON saas_runner_certificates"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_guard_runner_certificate_lifecycle()")
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_certificates_preview_gateway" '
            'ON "saas_runner_certificates"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_certificates_secret_broker" '
            'ON "saas_runner_certificates"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_certificates_platform" '
            'ON "saas_runner_certificates"'
        )
    op.drop_index("uq_runner_certificate_active", table_name="saas_runner_certificates")
    op.drop_index("ix_runner_certificate_rotation", table_name="saas_runner_certificates")
    op.drop_index("ix_runner_certificate_authorize", table_name="saas_runner_certificates")
    op.drop_table("saas_runner_certificates")
