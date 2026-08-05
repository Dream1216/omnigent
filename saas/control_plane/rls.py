"""Transaction-local PostgreSQL RLS context binding."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True)
class RlsContext:
    """Server-verified actor and Tenant used by PostgreSQL policies."""

    actor_id: UUID | None = None
    tenant_id: UUID | None = None
    space_id: UUID | None = None
    api_credential_id: UUID | None = None


def apply_rls_context(session: Session, context: RlsContext) -> None:
    """Bind RLS facts to the current transaction; never accept raw client values."""

    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    session.execute(
        sa.text("SELECT set_config('app.actor_id', :value, true)"),
        {"value": str(context.actor_id) if context.actor_id else ""},
    )
    session.execute(
        sa.text("SELECT set_config('app.tenant_id', :value, true)"),
        {"value": str(context.tenant_id) if context.tenant_id else ""},
    )
    session.execute(
        sa.text("SELECT set_config('app.space_id', :value, true)"),
        {"value": str(context.space_id) if context.space_id else ""},
    )
    session.execute(
        sa.text("SELECT set_config('app.api_credential_id', :value, true)"),
        {"value": str(context.api_credential_id) if context.api_credential_id else ""},
    )
