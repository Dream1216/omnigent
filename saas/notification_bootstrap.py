"""Publish the immutable built-in notification templates under Staff authority."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.notification_delivery import (
    NotificationActor,
    NotificationDeliveryService,
)
from saas.control_plane.notification_templates import NotificationTemplateBootstrap
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context
from saas.notification_runtime import notification_digesters

_LOGGER = logging.getLogger("omnigent-saas-notification-bootstrap")


def resolve_bootstrap_actor(
    sessions: sessionmaker[Session],
    *,
    principal_id: UUID,
    now: datetime,
) -> NotificationActor:
    """Derive current Staff permissions from the database, never from CLI input."""

    with sessions.begin() as db:
        apply_platform_rls_context(db, PlatformRlsContext(principal_id=principal_id))
        principal = db.get(PlatformStaffPrincipalRecord, principal_id)
        if principal is None or principal.status != "active":
            raise RuntimeError("notification bootstrap principal is not active")
        roles = tuple(
            db.execute(
                sa.select(PlatformRoleAssignmentRecord.role).where(
                    PlatformRoleAssignmentRecord.principal_id == principal_id,
                    PlatformRoleAssignmentRecord.status == "active",
                    sa.or_(
                        PlatformRoleAssignmentRecord.expires_at.is_(None),
                        PlatformRoleAssignmentRecord.expires_at > now,
                    ),
                )
            ).scalars()
        )
    permissions = frozenset(
        permission
        for role in roles
        for permission in PLATFORM_ROLE_PERMISSIONS.get(role, frozenset())
    )
    if "platform.notification_template.manage" not in permissions:
        raise RuntimeError("notification bootstrap principal lacks template authority")
    return NotificationActor(
        realm="staff",
        actor_id=principal_id,
        tenant_id=None,
        permissions=permissions,
    )


def verify_notification_bootstrap_database_role(engine: Engine) -> None:
    """Fail startup unless this is a narrow, non-emergency governance login."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production notification bootstrap requires PostgreSQL")
    with engine.connect() as connection:
        facts = connection.execute(
            sa.text(
                "SELECT current_user, role.rolsuper, role.rolbypassrls, "
                "pg_has_role(current_user, 'saas_platform_governance', 'member'), "
                "pg_has_role(current_user, 'saas_notification_dispatcher', 'member'), "
                "pg_has_role(current_user, 'saas_notification_scheduler', 'member'), "
                "pg_has_role(current_user, 'saas_platform', 'member') "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
    if facts[1] or facts[2] or not facts[3] or any(facts[index] for index in (4, 5, 6)):
        raise RuntimeError("notification bootstrap database role boundary is invalid")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("OMNIGENT_NOTIFICATION_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    database_url = _required_env("OMNIGENT_NOTIFICATION_BOOTSTRAP_DATABASE_URL")
    try:
        principal_id = UUID(
            _required_env("OMNIGENT_NOTIFICATION_BOOTSTRAP_PRINCIPAL_ID")
        )
    except ValueError as error:
        raise RuntimeError(
            "OMNIGENT_NOTIFICATION_BOOTSTRAP_PRINCIPAL_ID must be a UUID"
        ) from error
    engine = sa.create_engine(database_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
    try:
        verify_notification_bootstrap_database_role(engine)
        sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
        now = datetime.now(timezone.utc)
        actor = resolve_bootstrap_actor(sessions, principal_id=principal_id, now=now)
        current, previous = notification_digesters(
            {
                "hmac_key_id": _required_env("OMNIGENT_NOTIFICATION_HMAC_KEY_ID"),
                "hmac_secret_b64": _required_env(
                    "OMNIGENT_NOTIFICATION_HMAC_SECRET_B64"
                ),
                "previous_hmac_keys_json": os.environ.get(
                    "OMNIGENT_NOTIFICATION_PREVIOUS_HMAC_KEYS_JSON", "[]"
                ),
            }
        )
        delivery = NotificationDeliveryService(
            sessions,
            digester=current,
            previous_digesters=previous,
        )
        seeded = NotificationTemplateBootstrap(delivery).seed(actor, now=now)
        _LOGGER.info(
            "notification templates published",
            extra={
                "template_count": len(seeded),
                "replayed_count": sum(value.replayed for value in seeded),
            },
        )
        return 0
    finally:
        engine.dispose()


def _required_env(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(f"{key} is required")
    return value


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "main",
    "resolve_bootstrap_actor",
    "verify_notification_bootstrap_database_role",
]
