"""Durable ownership records for Runner WebSocket connection placement."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

RUNNER_TUNNEL_PLACEMENT_STATUSES = ("active", "draining", "released", "expired")


class RunnerTunnelPlacementRecord(SaasBase):
    """One immutable-generation lease naming the replica that owns a Runner tunnel."""

    __tablename__ = "saas_runner_tunnel_placements"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    runner_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT"), nullable=False
    )
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    routing_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    gateway_instance_id: Mapped[str] = mapped_column(
        sa.ForeignKey("saas_preview_gateway_instances.id", ondelete="RESTRICT"), nullable=False
    )
    relay_subject: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    ownership_token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    claimed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_heartbeat_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    release_reason: Mapped[str | None] = mapped_column(sa.String(256))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"status IN ({_values(RUNNER_TUNNEL_PLACEMENT_STATUSES)})",
            name="ck_runner_tunnel_placement_status",
        ),
        sa.CheckConstraint(
            "runner_connection_generation > 0",
            name="ck_runner_tunnel_placement_connection_generation",
        ),
        sa.CheckConstraint(
            "routing_generation > 0", name="ck_runner_tunnel_placement_routing_generation"
        ),
        sa.CheckConstraint(
            "length(gateway_instance_id) > 0",
            name="ck_runner_tunnel_placement_gateway_nonempty",
        ),
        sa.CheckConstraint(
            "length(relay_subject) > 0", name="ck_runner_tunnel_placement_relay_nonempty"
        ),
        sa.CheckConstraint(
            "length(ownership_token_hash) = 64",
            name="ck_runner_tunnel_placement_token_hash",
        ),
        sa.CheckConstraint(
            "last_heartbeat_at >= claimed_at",
            name="ck_runner_tunnel_placement_heartbeat_order",
        ),
        sa.CheckConstraint(
            "lease_expires_at > claimed_at",
            name="ck_runner_tunnel_placement_lease_window",
        ),
        sa.CheckConstraint(
            "(status IN ('active', 'draining') AND released_at IS NULL "
            "AND release_reason IS NULL) OR "
            "(status IN ('released', 'expired') AND released_at IS NOT NULL "
            "AND release_reason IS NOT NULL)",
            name="ck_runner_tunnel_placement_lifecycle",
        ),
        sa.UniqueConstraint(
            "runner_id",
            "routing_generation",
            name="uq_runner_tunnel_placement_generation",
        ),
        sa.Index(
            "ix_runner_tunnel_placement_resolve",
            "runner_id",
            "runner_connection_generation",
            "status",
            "lease_expires_at",
        ),
        sa.Index(
            "uq_runner_tunnel_placement_live",
            "runner_id",
            unique=True,
            postgresql_where=sa.text("status IN ('active', 'draining')"),
            sqlite_where=sa.text("status IN ('active', 'draining')"),
        ),
    )
