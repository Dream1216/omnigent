"""Associate local sessions with external identities and fence delayed logout."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "cd1b00000001"
down_revision = "cd1a00000001"
branch_labels = None
depends_on = None

_EXTERNAL_CHECK = (
    "(external_provider IS NULL AND external_issuer IS NULL AND external_subject IS NULL "
    "AND external_sid IS NULL AND external_issued_at IS NULL) OR "
    "(external_provider IS NOT NULL AND external_issuer IS NOT NULL "
    "AND external_subject IS NOT NULL "
    "AND length(external_provider) > 0 AND length(external_issuer) > 0 "
    "AND length(external_subject) > 0 AND external_issued_at IS NOT NULL "
    "AND authn_method = 'oidc:' || external_provider "
    "AND (external_sid IS NULL OR length(external_sid) > 0))"
)


def _owner(table: str) -> str:
    return (
        "current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
        f"WHERE oid = 'public.{table}'::regclass))"
    )


def upgrade() -> None:
    with op.batch_alter_table("saas_auth_sessions") as batch:
        for name, kind in (
            ("external_provider", sa.String(64)),
            ("external_issuer", sa.String(512)),
            ("external_subject", sa.String(512)),
            ("external_sid", sa.String(512)),
            ("external_issued_at", sa.DateTime(timezone=True)),
        ):
            batch.add_column(sa.Column(name, kind, nullable=True))
        batch.create_check_constraint("ck_auth_session_external_identity", _EXTERNAL_CHECK)
        batch.create_index(
            "ix_auth_session_external_subject", ["external_issuer", "external_subject"]
        )
        batch.create_index("ix_auth_session_external_sid", ["external_issuer", "external_sid"])
    op.create_table(
        "saas_oidc_session_fences",
        sa.Column("provider", sa.String(64), primary_key=True),
        sa.Column("issuer", sa.String(512), primary_key=True),
        sa.Column("kind", sa.String(32), primary_key=True),
        sa.Column("key_hash", sa.String(64), primary_key=True),
        sa.Column("logout_issued_at", sa.DateTime(timezone=True)),
        sa.Column("event_hash", sa.String(64)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "kind IN ('subject', 'subject_no_sid', 'sid', 'event')", name="ck_oidc_fence_kind"
        ),
        sa.CheckConstraint("length(key_hash) = 64", name="ck_oidc_fence_key_hash"),
        sa.CheckConstraint(
            "event_hash IS NULL OR (kind = 'event' AND length(event_hash) = 64)",
            name="ck_oidc_fence_event_hash",
        ),
        sa.CheckConstraint(
            "length(provider) > 0 AND length(issuer) > 0", name="ck_oidc_fence_provider"
        ),
    )
    if op.get_bind().dialect.name == "postgresql":
        table = "saas_oidc_session_fences"
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY rls_oidc_fences_authenticator ON {table} FOR ALL "
            "USING (pg_has_role(current_user, 'saas_authenticator', 'member')) "
            "WITH CHECK (pg_has_role(current_user, 'saas_authenticator', 'member'))"
        )
        op.execute(
            f"CREATE POLICY rls_oidc_fences_migration_read ON {table} "
            f"FOR SELECT USING ({_owner(table)})"
        )
        op.execute(
            "CREATE POLICY rls_auth_session_oidc_migration_read ON saas_auth_sessions "
            f"FOR SELECT USING (external_provider IS NOT NULL AND {_owner('saas_auth_sessions')})"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if (
        bind.execute(sa.text("SELECT 1 FROM saas_oidc_session_fences LIMIT 1")).first() is not None
        or bind.execute(
            sa.text("SELECT 1 FROM saas_auth_sessions WHERE external_provider IS NOT NULL LIMIT 1")
        ).first()
        is not None
    ):
        raise RuntimeError("retained federated sessions require application-only rollback")
    if bind.dialect.name == "postgresql":
        op.execute("DROP POLICY rls_auth_session_oidc_migration_read ON saas_auth_sessions")
    op.drop_table("saas_oidc_session_fences")
    with op.batch_alter_table("saas_auth_sessions") as batch:
        batch.drop_index("ix_auth_session_external_sid")
        batch.drop_index("ix_auth_session_external_subject")
        batch.drop_constraint("ck_auth_session_external_identity", type_="check")
        for name in (
            "external_provider",
            "external_issuer",
            "external_subject",
            "external_sid",
            "external_issued_at",
        ):
            batch.drop_column(name)
