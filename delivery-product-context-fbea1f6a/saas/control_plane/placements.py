"""Persistent cross-replica ownership for official Runner WebSocket tunnels."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.gateway_models import PreviewGatewayInstanceRecord
from saas.control_plane.placement_models import RunnerTunnelPlacementRecord
from saas.control_plane.scheduling_models import RunnerRegistrationRecord

_GATEWAY_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LIVE_STATUSES = frozenset(("active", "draining"))


class RunnerTunnelPlacementError(RuntimeError):
    """Stable fail-closed error for Runner tunnel placement operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RunnerTunnelPlacement:
    """Non-secret current route to the replica owning one Runner incarnation."""

    placement_id: UUID
    runner_id: UUID
    runner_connection_generation: int
    routing_generation: int
    gateway_instance_id: str
    relay_subject: str
    status: str
    lease_expires_at: datetime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _time(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value.astimezone(timezone.utc)


def _duration(value: timedelta, *, maximum: timedelta) -> None:
    if value <= timedelta(0) or value > maximum:
        raise RunnerTunnelPlacementError(
            "runner_tunnel_lease_invalid", "Runner tunnel lease duration is invalid"
        )


def _token_hash(token: str) -> str:
    if len(token) < 32 or len(token) > 512 or token.strip() != token or "\x00" in token:
        raise RunnerTunnelPlacementError(
            "runner_tunnel_token_invalid", "Runner tunnel ownership token is invalid"
        )
    return hashlib.sha256(token.encode()).hexdigest()


def _event(record: RunnerTunnelPlacementRecord, *, event_type: str) -> ControlPlaneOutboxEvent:
    payload: dict[str, object] = {
        "gateway_instance_id": record.gateway_instance_id,
        "placement_id": str(record.id),
        "routing_generation": record.routing_generation,
        "runner_connection_generation": record.runner_connection_generation,
        "runner_id": str(record.runner_id),
        "status": record.status,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    suffix = event_type.rsplit(".", 1)[-1]
    return ControlPlaneOutboxEvent(
        tenant_id=None,
        aggregate_type="runner_tunnel_placement",
        aggregate_key=str(record.id),
        event_type=event_type,
        payload=payload,
        idempotency_key=f"runner-tunnel-placement:{record.id}:{suffix}",
        request_hash=hashlib.sha256(encoded).hexdigest(),
    )


class RunnerTunnelPlacementAuthority:
    """Serialize Runner tunnel ownership and resolve it from every gateway replica."""

    def __init__(
        self,
        authority_session_factory: sessionmaker[Session],
        *,
        route_session_factory: sessionmaker[Session],
        gateway_instance_id: str,
        maximum_lease_duration: timedelta = timedelta(minutes=2),
    ) -> None:
        if not _GATEWAY_INSTANCE.fullmatch(gateway_instance_id):
            raise ValueError("gateway_instance_id is invalid")
        if maximum_lease_duration <= timedelta(0):
            raise ValueError("maximum_lease_duration must be positive")
        self._authority_session_factory = authority_session_factory
        self._route_session_factory = route_session_factory
        self.gateway_instance_id = gateway_instance_id
        self._maximum_lease_duration = maximum_lease_duration

    def claim_connection(
        self,
        *,
        runner_id: UUID,
        runner_connection_generation: int,
        runner_connection_token: str,
        ownership_token: str,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement:
        """Claim the current Runner incarnation, fencing an older incarnation immediately."""

        claimed_at = _time(now or _utcnow(), field="claim time")
        _duration(lease_duration, maximum=self._maximum_lease_duration)
        ownership_hash = _token_hash(ownership_token)
        connection_hash = _token_hash(runner_connection_token)
        if runner_connection_generation <= 0:
            raise RunnerTunnelPlacementError(
                "runner_tunnel_generation_invalid", "Runner connection generation is invalid"
            )

        with self._authority_session_factory.begin() as db:
            self._current_gateway(db, now=claimed_at, allow_draining=False)
            runner = self._current_runner(
                db,
                runner_id=runner_id,
                runner_connection_generation=runner_connection_generation,
                runner_connection_token_hash=connection_hash,
                lock=True,
            )
            existing_token = db.scalar(
                sa.select(RunnerTunnelPlacementRecord)
                .where(RunnerTunnelPlacementRecord.ownership_token_hash == ownership_hash)
                .with_for_update()
            )
            if existing_token is not None:
                if (
                    existing_token.runner_id == runner.id
                    and existing_token.runner_connection_generation == runner_connection_generation
                    and existing_token.gateway_instance_id == self.gateway_instance_id
                    and existing_token.status in _LIVE_STATUSES
                    and claimed_at < _aware(existing_token.lease_expires_at)
                ):
                    return self._receipt(existing_token)
                raise RunnerTunnelPlacementError(
                    "runner_tunnel_token_reused",
                    "Runner tunnel ownership token cannot be reused",
                )

            current = db.scalar(
                sa.select(RunnerTunnelPlacementRecord)
                .where(
                    RunnerTunnelPlacementRecord.runner_id == runner_id,
                    RunnerTunnelPlacementRecord.status.in_(tuple(_LIVE_STATUSES)),
                )
                .with_for_update()
            )
            if current is not None:
                if current.runner_connection_generation != runner_connection_generation:
                    self._finish(
                        db,
                        current,
                        status="released",
                        reason="runner_reconnected",
                        finished_at=claimed_at,
                    )
                elif claimed_at >= _aware(current.lease_expires_at):
                    self._finish(
                        db,
                        current,
                        status="expired",
                        reason="ownership_lease_expired",
                        finished_at=claimed_at,
                    )
                else:
                    raise RunnerTunnelPlacementError(
                        "runner_tunnel_already_owned",
                        "Runner tunnel is already owned by a live gateway replica",
                    )

            routing_generation = (
                int(
                    db.scalar(
                        sa.select(
                            sa.func.coalesce(
                                sa.func.max(RunnerTunnelPlacementRecord.routing_generation), 0
                            )
                        ).where(RunnerTunnelPlacementRecord.runner_id == runner_id)
                    )
                    or 0
                )
                + 1
            )
            placement_id = uuid4()
            record = RunnerTunnelPlacementRecord(
                id=placement_id,
                runner_id=runner_id,
                runner_connection_generation=runner_connection_generation,
                routing_generation=routing_generation,
                gateway_instance_id=self.gateway_instance_id,
                relay_subject=f"rtp_{placement_id.hex}",
                ownership_token_hash=ownership_hash,
                status="active",
                claimed_at=claimed_at,
                last_heartbeat_at=claimed_at,
                lease_expires_at=claimed_at + lease_duration,
            )
            db.add(record)
            db.flush()
            db.add(_event(record, event_type="runner.tunnel_placement.claimed"))
            return self._receipt(record)

    def heartbeat_connection(
        self,
        *,
        placement_id: UUID,
        runner_id: UUID,
        runner_connection_generation: int,
        runner_connection_token: str,
        ownership_token: str,
        routing_generation: int,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement:
        """Extend only the exact live owner and never revive an expired lease."""

        heartbeat_at = _time(now or _utcnow(), field="heartbeat time")
        _duration(lease_duration, maximum=self._maximum_lease_duration)
        connection_hash = _token_hash(runner_connection_token)
        ownership_hash = _token_hash(ownership_token)
        with self._authority_session_factory.begin() as db:
            self._current_gateway(db, now=heartbeat_at, allow_draining=True)
            self._current_runner(
                db,
                runner_id=runner_id,
                runner_connection_generation=runner_connection_generation,
                runner_connection_token_hash=connection_hash,
                lock=True,
            )
            record = self._owned_record(
                db,
                placement_id=placement_id,
                runner_id=runner_id,
                runner_connection_generation=runner_connection_generation,
                ownership_token_hash=ownership_hash,
                routing_generation=routing_generation,
                lock=True,
            )
            if record.status not in _LIVE_STATUSES or heartbeat_at >= _aware(
                record.lease_expires_at
            ):
                raise RunnerTunnelPlacementError(
                    "runner_tunnel_lease_stale", "Runner tunnel ownership lease is stale"
                )
            if heartbeat_at < _aware(record.last_heartbeat_at):
                raise RunnerTunnelPlacementError(
                    "runner_tunnel_time_reversed", "Runner tunnel heartbeat cannot move backwards"
                )
            record.last_heartbeat_at = heartbeat_at
            record.lease_expires_at = max(
                _aware(record.lease_expires_at), heartbeat_at + lease_duration
            )
            return self._receipt(record)

    def begin_draining(
        self,
        *,
        placement_id: UUID,
        runner_id: UUID,
        runner_connection_generation: int,
        ownership_token: str,
        routing_generation: int,
    ) -> bool:
        """Mark an exact owner draining while keeping existing routes valid."""

        ownership_hash = _token_hash(ownership_token)
        with self._authority_session_factory.begin() as db:
            record = self._owned_record(
                db,
                placement_id=placement_id,
                runner_id=runner_id,
                runner_connection_generation=runner_connection_generation,
                ownership_token_hash=ownership_hash,
                routing_generation=routing_generation,
                lock=True,
            )
            if record.status == "draining":
                return False
            if record.status != "active":
                raise RunnerTunnelPlacementError(
                    "runner_tunnel_placement_stale", "Runner tunnel placement is stale"
                )
            record.status = "draining"
            db.add(_event(record, event_type="runner.tunnel_placement.draining"))
            return True

    def release_connection(
        self,
        *,
        placement_id: UUID,
        runner_id: UUID,
        runner_connection_generation: int,
        ownership_token: str,
        routing_generation: int,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        """Release one exact owner idempotently; stale tokens cannot release replacements."""

        released_at = _time(now or _utcnow(), field="release time")
        ownership_hash = _token_hash(ownership_token)
        normalized_reason = " ".join(reason.split())
        if not normalized_reason or len(normalized_reason) > 256:
            raise RunnerTunnelPlacementError(
                "runner_tunnel_release_reason_invalid", "Runner tunnel release reason is invalid"
            )
        with self._authority_session_factory.begin() as db:
            record = self._owned_record(
                db,
                placement_id=placement_id,
                runner_id=runner_id,
                runner_connection_generation=runner_connection_generation,
                ownership_token_hash=ownership_hash,
                routing_generation=routing_generation,
                lock=True,
            )
            if record.status in {"released", "expired"}:
                return False
            if released_at < _aware(record.last_heartbeat_at):
                raise RunnerTunnelPlacementError(
                    "runner_tunnel_time_reversed", "Runner tunnel release cannot move backwards"
                )
            self._finish(
                db,
                record,
                status="released",
                reason=normalized_reason,
                finished_at=released_at,
            )
            return True

    def reconcile_expired(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> tuple[UUID, ...]:
        """Expire bounded stale ownership leases with SKIP LOCKED coordination."""

        reconciled_at = _time(now or _utcnow(), field="reconcile time")
        if limit <= 0 or limit > 1000:
            raise RunnerTunnelPlacementError(
                "runner_tunnel_reconcile_limit_invalid", "Reconcile limit is invalid"
            )
        expired: list[UUID] = []
        with self._authority_session_factory.begin() as db:
            query = (
                sa.select(RunnerTunnelPlacementRecord)
                .where(
                    RunnerTunnelPlacementRecord.status.in_(tuple(_LIVE_STATUSES)),
                    RunnerTunnelPlacementRecord.lease_expires_at <= reconciled_at,
                )
                .order_by(RunnerTunnelPlacementRecord.lease_expires_at)
                .limit(limit)
            )
            if db.get_bind().dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            else:
                query = query.with_for_update()
            for record in db.scalars(query):
                self._finish(
                    db,
                    record,
                    status="expired",
                    reason="ownership_lease_expired",
                    finished_at=reconciled_at,
                )
                expired.append(record.id)
        return tuple(expired)

    def resolve_preview_route(
        self,
        *,
        runner_id: UUID,
        runner_connection_generation: int,
        preview_token_hash: str,
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement:
        """Resolve an exact authorized Preview route to its current owning replica."""

        resolved_at = _time(now or _utcnow(), field="resolve time")
        digest = preview_token_hash.lower()
        if not _HEX_SHA256.fullmatch(digest) or runner_connection_generation <= 0:
            raise RunnerTunnelPlacementError(
                "runner_tunnel_route_invalid", "Preview Runner route is invalid"
            )
        with self._route_session_factory.begin() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text("SELECT set_config('app.preview_token_hash', :digest, true)"),
                    {"digest": digest},
                )
            row = db.execute(
                sa.select(
                    RunnerTunnelPlacementRecord,
                    RunnerRegistrationRecord,
                    PreviewGatewayInstanceRecord.status.label("gateway_status"),
                    PreviewGatewayInstanceRecord.lease_expires_at.label(
                        "gateway_lease_expires_at"
                    ),
                )
                .join(
                    RunnerRegistrationRecord,
                    RunnerRegistrationRecord.id == RunnerTunnelPlacementRecord.runner_id,
                )
                .join(
                    PreviewGatewayInstanceRecord,
                    PreviewGatewayInstanceRecord.id
                    == RunnerTunnelPlacementRecord.gateway_instance_id,
                )
                .where(
                    RunnerTunnelPlacementRecord.runner_id == runner_id,
                    RunnerTunnelPlacementRecord.runner_connection_generation
                    == runner_connection_generation,
                    RunnerTunnelPlacementRecord.status.in_(tuple(_LIVE_STATUSES)),
                )
            ).first()
            if row is None:
                raise RunnerTunnelPlacementError(
                    "runner_tunnel_route_unavailable", "Runner tunnel route is unavailable"
                )
            record, runner, gateway_status, gateway_lease_expires_at = row
            if (
                runner.status not in {"online", "draining"}
                or runner.connection_generation != runner_connection_generation
                or resolved_at >= _aware(record.lease_expires_at)
                or gateway_status not in _LIVE_STATUSES
                or resolved_at >= _aware(gateway_lease_expires_at)
            ):
                raise RunnerTunnelPlacementError(
                    "runner_tunnel_route_stale", "Runner tunnel route is stale"
                )
            return self._receipt(record)

    def require_route_owner(
        self,
        *,
        placement: RunnerTunnelPlacement,
        runner_id: UUID,
        runner_connection_generation: int,
        preview_token_hash: str,
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement:
        """Re-resolve on the receiving replica before accepting a relayed request."""

        current = self.resolve_preview_route(
            runner_id=runner_id,
            runner_connection_generation=runner_connection_generation,
            preview_token_hash=preview_token_hash,
            now=now,
        )
        stable_current = (
            current.placement_id,
            current.runner_id,
            current.runner_connection_generation,
            current.routing_generation,
            current.gateway_instance_id,
            current.relay_subject,
        )
        stable_supplied = (
            placement.placement_id,
            placement.runner_id,
            placement.runner_connection_generation,
            placement.routing_generation,
            placement.gateway_instance_id,
            placement.relay_subject,
        )
        if (
            stable_current != stable_supplied
            or current.gateway_instance_id != self.gateway_instance_id
        ):
            raise RunnerTunnelPlacementError(
                "runner_tunnel_route_owner_changed", "Runner tunnel route owner changed"
            )
        return current

    def _current_gateway(
        self,
        db: Session,
        *,
        now: datetime,
        allow_draining: bool,
    ) -> None:
        row = db.execute(
            sa.select(
                PreviewGatewayInstanceRecord.id,
                PreviewGatewayInstanceRecord.status,
                PreviewGatewayInstanceRecord.lease_expires_at,
            ).where(PreviewGatewayInstanceRecord.id == self.gateway_instance_id)
        ).one_or_none()
        accepted = _LIVE_STATUSES if allow_draining else frozenset(("active",))
        if row is None or row.status not in accepted or now >= _aware(row.lease_expires_at):
            raise RunnerTunnelPlacementError(
                "runner_tunnel_gateway_stale", "Runner tunnel Gateway instance is stale"
            )

    @staticmethod
    def _current_runner(
        db: Session,
        *,
        runner_id: UUID,
        runner_connection_generation: int,
        runner_connection_token_hash: str,
        lock: bool,
    ) -> RunnerRegistrationRecord:
        query = sa.select(RunnerRegistrationRecord).where(RunnerRegistrationRecord.id == runner_id)
        if lock:
            query = query.with_for_update()
        runner = db.scalar(query)
        if (
            runner is None
            or runner.status not in {"online", "draining"}
            or runner.connection_generation != runner_connection_generation
            or not hmac.compare_digest(runner.connection_token_hash, runner_connection_token_hash)
        ):
            raise RunnerTunnelPlacementError(
                "runner_tunnel_connection_stale", "Runner connection is stale"
            )
        return runner

    def _owned_record(
        self,
        db: Session,
        *,
        placement_id: UUID,
        runner_id: UUID,
        runner_connection_generation: int,
        ownership_token_hash: str,
        routing_generation: int,
        lock: bool,
    ) -> RunnerTunnelPlacementRecord:
        query = sa.select(RunnerTunnelPlacementRecord).where(
            RunnerTunnelPlacementRecord.id == placement_id
        )
        if lock:
            query = query.with_for_update()
        record = db.scalar(query)
        if (
            record is None
            or record.runner_id != runner_id
            or record.runner_connection_generation != runner_connection_generation
            or record.routing_generation != routing_generation
            or record.gateway_instance_id != self.gateway_instance_id
            or not hmac.compare_digest(record.ownership_token_hash, ownership_token_hash)
        ):
            raise RunnerTunnelPlacementError(
                "runner_tunnel_placement_stale", "Runner tunnel placement is stale"
            )
        return record

    @staticmethod
    def _finish(
        db: Session,
        record: RunnerTunnelPlacementRecord,
        *,
        status: str,
        reason: str,
        finished_at: datetime,
    ) -> None:
        record.status = status
        record.released_at = finished_at
        record.release_reason = reason
        db.add(_event(record, event_type=f"runner.tunnel_placement.{status}"))

    @staticmethod
    def _receipt(record: RunnerTunnelPlacementRecord) -> RunnerTunnelPlacement:
        return RunnerTunnelPlacement(
            placement_id=record.id,
            runner_id=record.runner_id,
            runner_connection_generation=record.runner_connection_generation,
            routing_generation=record.routing_generation,
            gateway_instance_id=record.gateway_instance_id,
            relay_subject=record.relay_subject,
            status=record.status,
            lease_expires_at=_aware(record.lease_expires_at),
        )
