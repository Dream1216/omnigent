"""Credential-free identity event receipts and per-connection provider state."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import IdentityConnection, SaasBase, _hex64


def provider_identity_available():
    """Allow missing rollout rows; reject observed disabled or deleted identities."""
    return ~sa.exists(
        sa.select(1).where(
            IdentityProviderStateRecord.connection_id == IdentityConnection.id,
            IdentityProviderStateRecord.status != "active",
        )
    )


class IdentityProviderStateRecord(SaasBase):
    __tablename__ = "saas_identity_provider_states"

    connection_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_identity_connections.id", ondelete="RESTRICT"), primary_key=True
    )
    subject_locator_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    username_locator_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, server_default="active")
    snapshot_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    password_revision_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    password_changed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    checked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    next_check_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    claim_token: Mapped[UUID | None] = mapped_column()
    claim_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(nullable=False, server_default="0")
    last_error_code: Mapped[str | None] = mapped_column(sa.String(64))
    version: Mapped[int] = mapped_column(nullable=False, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('active','disabled','deleted')", name="ck_identity_provider_state_status"
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND version > 0", name="ck_identity_provider_state_versions"
        ),
        sa.CheckConstraint(
            _hex64("subject_locator_sha256"), name="ck_identity_provider_state_subject"
        ),
        *[
            sa.CheckConstraint(
                column + " IS NULL OR (" + _hex64(column) + ")",
                name="ck_identity_provider_state_" + column,
            )
            for column in (
                "username_locator_sha256",
                "snapshot_sha256",
                "password_revision_sha256",
                "claim_sha256",
            )
        ],
        sa.CheckConstraint(
            "(claim_token IS NULL) = (lease_expires_at IS NULL) AND "
            "(claim_token IS NULL) = (claim_sha256 IS NULL)",
            name="ck_identity_provider_state_lease",
        ),
        sa.CheckConstraint(
            "checked_at IS NULL OR snapshot_sha256 IS NOT NULL",
            name="ck_identity_provider_state_snapshot",
        ),
        sa.Index("ix_identity_provider_state_subject", "subject_locator_sha256"),
        sa.Index("ix_identity_provider_state_username", "username_locator_sha256"),
        sa.Index("ix_identity_provider_state_due", "next_check_at", "lease_expires_at"),
    )


class IdentityEventInboxRecord(SaasBase):
    __tablename__ = "saas_identity_event_inbox"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    organization: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    event_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    action: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    security_event: Mapped[bool] = mapped_column(nullable=False, server_default=sa.false())
    subject_locator_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    username_locator_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    request_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, server_default="pending")
    attempt_count: Mapped[int] = mapped_column(nullable=False, server_default="0")
    available_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    claim_token: Mapped[UUID | None] = mapped_column()
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    processed_connection_count: Mapped[int] = mapped_column(nullable=False, server_default="0")
    last_error_code: Mapped[str | None] = mapped_column(sa.String(64))
    version: Mapped[int] = mapped_column(nullable=False, server_default="1")

    __table_args__ = (
        sa.UniqueConstraint(
            "issuer", "organization", "event_id", name="uq_identity_inbox_provider_event"
        ),
        sa.CheckConstraint(
            "provider='casdoor' AND length(issuer)>0 AND length(organization)>0 "
            "AND length(event_id)>0",
            name="ck_identity_inbox_source",
        ),
        sa.CheckConstraint(
            "action IN ('update-user','delete-user','set-password')",
            name="ck_identity_inbox_action",
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','retry','completed','ignored','dead')",
            name="ck_identity_inbox_status",
        ),
        sa.CheckConstraint(
            "attempt_count>=0 AND version>0 AND processed_connection_count>=0",
            name="ck_identity_inbox_versions",
        ),
        *[
            sa.CheckConstraint(_hex64(column), name="ck_identity_inbox_" + column)
            for column in ("username_locator_sha256", "request_sha256")
        ],
        sa.CheckConstraint(
            "subject_locator_sha256 IS NULL OR (" + _hex64("subject_locator_sha256") + ")",
            name="ck_identity_inbox_subject",
        ),
        sa.CheckConstraint(
            "(claim_token IS NULL AND lease_expires_at IS NULL AND status<>'processing') OR "
            "(claim_token IS NOT NULL AND lease_expires_at IS NOT NULL AND status='processing')",
            name="ck_identity_inbox_lease",
        ),
        sa.CheckConstraint(
            "(status IN ('completed','ignored','dead')) = (completed_at IS NOT NULL)",
            name="ck_identity_inbox_completion",
        ),
        sa.Index("ix_identity_inbox_due", "status", "available_at", "lease_expires_at"),
    )
