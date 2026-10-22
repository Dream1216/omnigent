"""Add local Staff password credentials and disable strong-auth admission.

Revision ID: p0s000000014
Revises: p0s000000013
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000014"
down_revision: str | None = "p0s000000013"
branch_labels: str | None = None
depends_on: str | None = None

_CREDENTIALS = "saas_platform_password_credentials"
_SESSIONS = "saas_platform_auth_sessions"
_IDENTITY_ISSUER = "NULLIF(current_setting('app.platform_identity_issuer', true), '')"
_IDENTITY_SUBJECT = "NULLIF(current_setting('app.platform_identity_subject', true), '')"
_AUTHENTICATOR = "pg_has_role(current_user, 'saas_platform_authenticator', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def upgrade() -> None:
    op.create_table(
        _CREDENTIALS,
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("username_normalized", sa.String(128), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("password_version", sa.Integer(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(username_normalized) >= 3",
            name="ck_platform_password_username_nonempty",
        ),
        sa.CheckConstraint(
            "length(password_hash) > 0",
            name="ck_platform_password_hash_nonempty",
        ),
        sa.CheckConstraint(
            "password_version > 0",
            name="ck_platform_password_version",
        ),
        sa.CheckConstraint(
            "failed_attempts >= 0",
            name="ck_platform_password_failed_attempts",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("principal_id"),
        sa.UniqueConstraint("username_normalized", name="uq_platform_password_username"),
    )
    op.create_index("ix_platform_password_lock", _CREDENTIALS, ["locked_until"])

    with op.batch_alter_table(_SESSIONS) as batch:
        batch.drop_constraint("ck_platform_session_mfa_strength", type_="check")
        batch.create_check_constraint(
            "ck_platform_session_mfa_strength",
            "mfa_strength IN ('not_required', 'phishing_resistant')",
        )

    if op.get_bind().dialect.name != "postgresql":
        return

    op.execute(f"ALTER TABLE {_CREDENTIALS} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_CREDENTIALS} FORCE ROW LEVEL SECURITY")
    exact_identity = (
        f"({_AUTHENTICATOR} AND {_IDENTITY_ISSUER} = 'urn:omnigent:staff-password' "
        f"AND username_normalized = {_IDENTITY_SUBJECT})"
    )
    recovery = f"({_GOVERNANCE} OR {_EMERGENCY})"
    op.execute(
        'CREATE POLICY "rls_platform_password_authenticator" '
        f"ON {_CREDENTIALS} FOR SELECT TO saas_platform_authenticator "
        f"USING ({exact_identity})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_password_attempt_update" '
        f"ON {_CREDENTIALS} FOR UPDATE TO saas_platform_authenticator "
        f"USING ({exact_identity}) WITH CHECK ({exact_identity})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_password_governance" '
        f"ON {_CREDENTIALS} FOR ALL TO saas_platform_governance, saas_platform "
        f"USING ({recovery}) WITH CHECK ({recovery})"
    )
    op.execute(
        f"GRANT SELECT, UPDATE (password_hash, failed_attempts, locked_until, updated_at) "
        f"ON {_CREDENTIALS} TO saas_platform_authenticator"
    )
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_CREDENTIALS} "
        "TO saas_platform_governance, saas_platform"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"ALTER TABLE {_SESSIONS} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"DELETE FROM {_SESSIONS} WHERE mfa_strength = 'not_required'")
        op.execute(f"ALTER TABLE {_SESSIONS} FORCE ROW LEVEL SECURITY")
    else:
        op.execute(f"DELETE FROM {_SESSIONS} WHERE mfa_strength = 'not_required'")
    with op.batch_alter_table(_SESSIONS) as batch:
        batch.drop_constraint("ck_platform_session_mfa_strength", type_="check")
        batch.create_check_constraint(
            "ck_platform_session_mfa_strength",
            "mfa_strength = 'phishing_resistant'",
        )
    op.drop_table(_CREDENTIALS)
