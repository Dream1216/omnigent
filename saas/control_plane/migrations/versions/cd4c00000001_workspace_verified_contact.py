"""Admit authoritative phone ownership at the workspace intent RLS boundary."""

from __future__ import annotations

from alembic import op

revision = "cd4c00000001"
down_revision = "cd4b00000001"
branch_labels = None
depends_on = None

_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_PREFIX = (
    f"user_id = {_ACTOR} AND source = 'authenticated' AND registration_id IS NULL "
    "AND status = 'ready' AND EXISTS (SELECT 1 FROM saas_global_users u "
    f"WHERE u.id = {_ACTOR} AND u.status = 'active') AND "
)


def _apply(verified: str) -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER POLICY rls_creation_intent_actor_insert ON saas_tenant_creation_intents "
            f"WITH CHECK ({_PREFIX}{verified})"
        )


def upgrade() -> None:
    _apply(
        "EXISTS (SELECT 1 FROM saas_identity_connections i "
        f"WHERE i.user_id = {_ACTOR} AND i.status = 'active' "
        "AND NOT EXISTS (SELECT 1 FROM saas_identity_provider_states unavailable "
        "WHERE unavailable.connection_id = i.id AND unavailable.status <> 'active') "
        "AND ((i.email_verified AND i.email_normalized IS NOT NULL) OR "
        "(i.provider = 'casdoor' AND i.phone_verified AND i.phone_e164 IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM saas_identity_provider_states verified "
        "WHERE verified.connection_id = i.id AND verified.status = 'active' "
        "AND verified.checked_at IS NOT NULL))))"
    )


def downgrade() -> None:
    _apply(
        "EXISTS (SELECT 1 FROM saas_identity_connections i "
        f"WHERE i.user_id = {_ACTOR} AND i.status = 'active' "
        "AND i.email_verified AND i.email_normalized IS NOT NULL)"
    )
