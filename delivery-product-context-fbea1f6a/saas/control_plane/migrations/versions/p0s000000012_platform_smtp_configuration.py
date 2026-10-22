"""Add governed Platform SMTP configuration and content-blind receipts.

Revision ID: p0s000000012
Revises: p0s000000011
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000012"
down_revision: str | None = "p0s000000011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONFIGURATION = "saas_email_provider_configurations"
_RECEIPTS = "saas_email_provider_configuration_receipts"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_APP = "pg_has_role(current_user, 'saas_platform_app', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_ONBOARDING = "pg_has_role(current_user, 'saas_onboarding', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _active_assignment(*roles: str) -> str:
    allowed = ", ".join(f"'{role}'" for role in roles)
    return (
        "EXISTS (SELECT 1 FROM saas_platform_role_assignments smtp_assignment "
        f"WHERE smtp_assignment.principal_id = {_PRINCIPAL} "
        f"AND smtp_assignment.role IN ({allowed}) "
        "AND smtp_assignment.status = 'active' "
        "AND (smtp_assignment.expires_at IS NULL "
        "OR smtp_assignment.expires_at > CURRENT_TIMESTAMP))"
    )


def _create_tables() -> None:
    op.create_table(
        _CONFIGURATION,
        sa.Column("purpose", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("security", sa.String(16), nullable=False),
        sa.Column("username", sa.String(320), nullable=False),
        sa.Column("password_ciphertext", sa.Text(), nullable=False),
        sa.Column("from_address", sa.String(320), nullable=False),
        sa.Column("reply_to_address", sa.String(320)),
        sa.Column("timeout_seconds", sa.Float(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('onboarding_verification')",
            name="ck_email_provider_configuration_purpose",
        ),
        sa.CheckConstraint(
            "security IN ('starttls', 'tls')",
            name="ck_email_provider_configuration_security",
        ),
        sa.CheckConstraint(
            "port >= 1 AND port <= 65535",
            name="ck_email_provider_configuration_port",
        ),
        sa.CheckConstraint(
            "timeout_seconds > 0 AND timeout_seconds <= 30",
            name="ck_email_provider_configuration_timeout",
        ),
        sa.CheckConstraint(
            "version > 0",
            name="ck_email_provider_configuration_version",
        ),
        sa.CheckConstraint(
            "length(host) > 0 AND length(username) > 0 AND "
            "length(password_ciphertext) > 0 AND length(from_address) > 0",
            name="ck_email_provider_configuration_required_values",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("purpose"),
    )
    op.create_table(
        _RECEIPTS,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(64), nullable=False),
        sa.Column("configuration_version", sa.Integer(), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("configuration_hash", sa.String(64), nullable=False),
        sa.Column("password_rotated", sa.Boolean(), nullable=False),
        sa.Column("recipient_hash", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('onboarding_verification')",
            name="ck_email_provider_receipt_purpose",
        ),
        sa.CheckConstraint(
            "action IN ('configured', 'disabled', 'test_succeeded', 'test_failed')",
            name="ck_email_provider_receipt_action",
        ),
        sa.CheckConstraint(
            "configuration_version > 0",
            name="ck_email_provider_receipt_version",
        ),
        sa.CheckConstraint(
            "length(configuration_hash) = 64",
            name="ck_email_provider_receipt_hash",
        ),
        sa.CheckConstraint(
            "recipient_hash IS NULL OR length(recipient_hash) = 64",
            name="ck_email_provider_receipt_recipient_hash",
        ),
        sa.ForeignKeyConstraint(
            ["actor_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_email_provider_receipt_purpose_time",
        _RECEIPTS,
        ("purpose", "occurred_at", "id"),
    )


def _create_postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in (_CONFIGURATION, _RECEIPTS):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    app_read = (
        f"({_APP} AND {_PRINCIPAL} IS NOT NULL AND "
        f"{_active_assignment('platform_operator', 'platform_security_auditor')})"
    )
    app_write = (
        f"({_APP} AND {_PRINCIPAL} IS NOT NULL AND {_active_assignment('platform_operator')})"
    )
    recovery = f"({_EMERGENCY} OR {_GOVERNANCE})"
    config_write = f"({app_write} AND updated_by_principal_id = {_PRINCIPAL})"
    receipt_insert = f"({app_write} AND actor_principal_id = {_PRINCIPAL})"
    op.execute(
        'CREATE POLICY "rls_email_provider_configuration_app_read" '
        f"ON {_CONFIGURATION} FOR SELECT TO saas_platform_app USING ({app_read})"
    )
    op.execute(
        'CREATE POLICY "rls_email_provider_configuration_onboarding_read" '
        f"ON {_CONFIGURATION} FOR SELECT TO saas_onboarding USING ({_ONBOARDING})"
    )
    op.execute(
        'CREATE POLICY "rls_email_provider_configuration_app_insert" '
        f"ON {_CONFIGURATION} FOR INSERT TO saas_platform_app WITH CHECK ({config_write})"
    )
    op.execute(
        'CREATE POLICY "rls_email_provider_configuration_app_update" '
        f"ON {_CONFIGURATION} FOR UPDATE TO saas_platform_app "
        f"USING ({app_write}) WITH CHECK ({config_write})"
    )
    op.execute(
        'CREATE POLICY "rls_email_provider_configuration_recovery" '
        f"ON {_CONFIGURATION} FOR ALL TO saas_platform, saas_platform_governance "
        f"USING ({recovery}) WITH CHECK ({recovery})"
    )
    op.execute(
        'CREATE POLICY "rls_email_provider_receipt_app_read" '
        f"ON {_RECEIPTS} FOR SELECT TO saas_platform_app USING ({app_read})"
    )
    op.execute(
        'CREATE POLICY "rls_email_provider_receipt_app_insert" '
        f"ON {_RECEIPTS} FOR INSERT TO saas_platform_app WITH CHECK ({receipt_insert})"
    )
    op.execute(
        'CREATE POLICY "rls_email_provider_receipt_recovery" '
        f"ON {_RECEIPTS} FOR ALL TO saas_platform, saas_platform_governance "
        f"USING ({recovery}) WITH CHECK ({recovery})"
    )

    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_CONFIGURATION} TO saas_platform_app")
    op.execute(f"GRANT SELECT, INSERT ON {_RECEIPTS} TO saas_platform_app")
    op.execute(f"GRANT SELECT ON {_CONFIGURATION} TO saas_onboarding")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_CONFIGURATION} TO saas_platform_governance"
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_RECEIPTS} TO saas_platform_governance")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_CONFIGURATION} TO saas_platform")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_RECEIPTS} TO saas_platform")


def upgrade() -> None:
    _create_tables()
    _create_postgresql_authority()


def downgrade() -> None:
    op.drop_table(_RECEIPTS)
    op.drop_table(_CONFIGURATION)
