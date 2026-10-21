"""Bounded real snapshot/key invalidation cache and per-process delivery ACKs."""

from __future__ import annotations

import hashlib
import heapq
import json
import re
import threading
import time
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
from saas.control_plane.context_snapshot import context_snapshot_epoch_grace_seconds
from saas.control_plane.db_models import ControlPlaneOutboxEvent, GlobalUser
from saas.control_plane.outbox import OutboxClaimRoute, OutboxPublishError
from saas.control_plane.outbox_delivery import delivery_source, native_delivery_row
from saas.control_plane.outbox_delivery_models import RevocationReplicaAppliedRecord
from saas.observability import SloMetrics

REVOCATION_ROUTES = {
    "user": ("authorization_user", "authorization.user.version_changed"),
    "service_account": (
        "authorization_service_account",
        "authorization.service_account.version_changed",
    ),
    "api_credential": ("authorization_api_credential", "authorization.api_credential.revoked"),
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class RevocationCacheUnavailable(RuntimeError):
    """Degraded fallback must stop while invalidation delivery is unqualified."""


class AuthorizationInvalidations:
    """Denial-only hints; never a cache that authorizes a request without live DB.

    Entries outlive the original sixty-second Snapshot TTL plus clock allowance.
    Expiry cannot allow an expired Snapshot; API keys still require original live
    validation. Overflow/disconnection disables degraded fallback rather than
    silently dropping an invalidation. Lookups never scan the cache/history.
    """

    def __init__(self, *, maximum_records: int = 65536, clock=time.monotonic) -> None:
        if not 1 <= maximum_records <= 1_000_000:
            raise ValueError("invalidation cache bound is invalid")
        self._maximum = maximum_records
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, UUID], tuple[int, float]] = {}
        self._expiry: list[tuple[float, str, UUID]] = []
        self._caught_up = False
        self._epoch_not_before: float | None = None

    @property
    def ready(self) -> bool:
        with self._lock:
            return (
                self._caught_up
                and self._epoch_not_before is not None
                and self._clock() >= self._epoch_not_before
            )

    def begin_listener_epoch(self) -> None:
        """Only a new actual LISTEN epoch starts the old-snapshot expiry barrier.

        P15 writers need not have produced a typed event. Catch-up alone cannot
        attest their old snapshots invalid; all of those must naturally expire.
        This monotonic barrier never replaces original wall-clock token expiry.
        """
        with self._lock:
            self._caught_up = False
            self._epoch_not_before = self._clock() + context_snapshot_epoch_grace_seconds()

    def unavailable(self) -> None:
        with self._lock:
            self._caught_up = False

    def caught_up(self) -> None:
        with self._lock:
            self._caught_up = True

    def minimum(self, kind: str, entity_id: UUID) -> int:
        with self._lock:
            found = self._entries.get((kind, entity_id))
            if found is None:
                return 0
            if found[1] <= self._clock():
                del self._entries[(kind, entity_id)]
                return 0
            return found[0]

    def apply(self, kind: str, entity_id: UUID, version_floor: int) -> int:
        if kind not in REVOCATION_ROUTES or type(version_floor) is not int or version_floor < 1:
            raise RevocationCacheUnavailable("invalidation fact is invalid")
        with self._lock:
            now = self._clock()
            # Bound maintenance too: a request never scans all cached identities.
            for _ in range(128):
                if not self._expiry or self._expiry[0][0] > now:
                    break
                until, old_kind, old_id = heapq.heappop(self._expiry)
                old = self._entries.get((old_kind, old_id))
                if old is not None and old[1] == until:
                    del self._entries[(old_kind, old_id)]
            key = kind, entity_id
            previous = self.minimum(kind, entity_id)
            if key not in self._entries and len(self._entries) >= self._maximum:
                self.unavailable()
                raise RevocationCacheUnavailable("invalidation capacity exhausted")
            effective = max(previous, version_floor)
            until = now + 120.0
            self._entries[key] = effective, until
            heapq.heappush(self._expiry, (until, kind, entity_id))
            if len(self._expiry) > self._maximum * 4:
                self._expiry = [(value[1], key[0], key[1]) for key, value in self._entries.items()]
                heapq.heapify(self._expiry)
            return effective


class ReplicaRevocationConsumer:
    """A source event produces an ACK only after actual cache application/readback.

    This is a fanout consumer, not the generic single-publisher dispatcher. The
    production driver uses native commit notifications and explicit bounded
    reconnect scans. It must not mark the original Outbox published merely on
    this one replica's receipt.
    """

    def __init__(
        self,
        factory: sessionmaker[Session],
        cache: AuthorizationInvalidations,
        *,
        product_revision: str,
        replica_uid: UUID,
        metrics: SloMetrics | None = None,
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
            raise ValueError("revocation consumer requires an exact Product SHA")
        self.factory, self.cache = factory, cache
        self.product_revision, self.replica_uid = product_revision, replica_uid
        self.process_boot_uid = uuid4()  # Pod UID alone survives container restarts.
        self.listener_epoch_uid = uuid4()  # Reconnect cannot reuse the prior connection ACK.
        self.metrics = metrics

    def _identity(self, event_id: UUID):
        return (
            event_id,
            self.replica_uid,
            self.process_boot_uid,
            self.listener_epoch_uid,
            self.product_revision,
        )

    @staticmethod
    def _source(db: Session, event_id: UUID):
        source = delivery_source(db, "revocation", event_id)
        if source is None or not isinstance(source.payload, dict):
            raise OutboxPublishError(
                "revocation_source_missing", retryable=True, pre_side_effect=True
            )
        body = source.payload
        if set(body) not in (
            {"kind", "entity_id", "version_floor"},
            {"kind", "entity_id", "version_floor", "deleted"},
        ):
            raise OutboxPublishError(
                "revocation_source_invalid", retryable=False, pre_side_effect=True
            )
        kind = body.get("kind")
        if (
            kind not in REVOCATION_ROUTES
            or (source.aggregate_type, source.event_type) != REVOCATION_ROUTES[kind]
        ):
            raise OutboxPublishError(
                "revocation_route_invalid", retryable=False, pre_side_effect=True
            )
        try:
            entity = UUID(cast(str, body["entity_id"]))
        except (ValueError, TypeError, AttributeError):
            raise OutboxPublishError(
                "revocation_entity_invalid", retryable=False, pre_side_effect=True
            ) from None
        floor = body["version_floor"]
        if (
            type(floor) is not int
            or floor < 1
            or source.aggregate_key != str(entity)
            or source.request_hash != _hash(body)
        ):
            raise OutboxPublishError(
                "revocation_source_mismatch", retryable=False, pre_side_effect=True
            )
        model = {
            "user": GlobalUser,
            "service_account": ServiceAccountRecord,
            "api_credential": ApiCredentialRecord,
        }[kind]
        # The consumer login has no permission to read API token hashes or
        # user PII. Do not use an ORM entity load that expands SELECT *.
        if kind == "api_credential":
            columns = (
                ApiCredentialRecord.id,
                ApiCredentialRecord.status,
                ApiCredentialRecord.revoked_at,
            )
        elif kind == "user":
            columns = (GlobalUser.id, GlobalUser.status, GlobalUser.security_version)
        else:
            columns = (
                ServiceAccountRecord.id,
                ServiceAccountRecord.status,
                ServiceAccountRecord.security_version,
            )
        if db.get_bind().dialect.name == "postgresql":
            authority = native_delivery_row(db, "revocation_authority", event_id)
            actual = (
                None
                if authority is None
                else (
                    authority.id,
                    authority.status,
                    authority.revoked_at
                    if kind == "api_credential"
                    else authority.security_version,
                )
            )
        else:
            actual = db.execute(sa.select(*columns).where(model.id == entity)).first()
        deleted = body.get("deleted", False)
        if type(deleted) is not bool or (actual is None and not deleted):
            raise OutboxPublishError(
                "revocation_authority_missing", retryable=True, pre_side_effect=True
            )
        if actual is not None:
            if kind == "api_credential":
                if actual[1] == "active" and actual[2] is None:
                    raise OutboxPublishError(
                        "revocation_not_committed", retryable=True, pre_side_effect=True
                    )
            elif actual[2] < floor:
                raise OutboxPublishError(
                    "revocation_version_uncommitted", retryable=True, pre_side_effect=True
                )
        return source, kind, entity, floor

    def consume(self, event_id: UUID, *, recovery: bool = False) -> bool:
        try:
            with self.factory.begin() as db:
                source, kind, entity, floor = self._source(db, event_id)
                old = db.get(RevocationReplicaAppliedRecord, self._identity(event_id))
                effective = self.cache.apply(kind, entity, floor)
                if self.cache.minimum(kind, entity) < floor:
                    raise RevocationCacheUnavailable("actual cache readback is below source floor")
                effect = {
                    "event_id": str(event_id),
                    "kind": kind,
                    "entity_id": str(entity),
                    "source_floor": floor,
                    "effective_floor": effective,
                    "replica_uid": str(self.replica_uid),
                    "process_boot_uid": str(self.process_boot_uid),
                    "listener_epoch_uid": str(self.listener_epoch_uid),
                    "product_revision": self.product_revision,
                }
                if old is None:
                    db.add(
                        RevocationReplicaAppliedRecord(
                            outbox_event_id=event_id,
                            replica_uid=self.replica_uid,
                            process_boot_uid=self.process_boot_uid,
                            listener_epoch_uid=self.listener_epoch_uid,
                            product_revision=self.product_revision,
                            version_floor=effective,
                            applied_digest=_hash(effect),
                            source_created_at=source.created_at,
                        )
                    )
                elif old.version_floor < floor:
                    raise RevocationCacheUnavailable(
                        "immutable previous ACK is below source floor"
                    )
            # A new Session observes the durable ACK. No caller-supplied ready flag.
            with self.factory() as db, db.begin():
                receipt = db.get(RevocationReplicaAppliedRecord, self._identity(event_id))
                if receipt is None or receipt.version_floor < floor:
                    raise RevocationCacheUnavailable("durable replica ACK is not visible")
                origin = receipt.source_created_at
            if self.metrics is not None:
                origin = (
                    origin.replace(tzinfo=UTC) if origin.tzinfo is None else origin.astimezone(UTC)
                )
                elapsed = (datetime.now(UTC) - origin).total_seconds()
                if elapsed < 0:
                    raise RevocationCacheUnavailable("revocation observer clock is invalid")
                # Producer created_at precedes commit, so this is a conservative
                # upper bound. History/new events applied before fallback Ready
                # have a separate recovery age/count, never real-time success.
                outcome = "replayed" if recovery or old else "success"
                self.metrics.duration("revocation_invalidation", outcome, elapsed)
                self.metrics.count(
                    "revocation_degraded" if recovery else "revocation_healthy", outcome
                )
            return old is None
        except Exception:
            self.cache.unavailable()
            if self.metrics is not None:
                self.metrics.count("coverage_gap", "blocked")
            raise


class NativeRevocationFollower:
    """LISTEN first, then bounded full-source catch-up on every new connection.

    UUID order is only a bounded scan cursor, never a commit watermark. A commit
    behind that cursor arrives on the already-active native notification stream.
    Disconnect/overflow forces a new complete bounded scan before fallback Ready.
    Published source events remain included: a replacement process cannot borrow
    another process's ACK. This follower never marks a fanout source published.
    """

    channel = "saas_authorization_invalidation_v1"

    def __init__(self, consumer: ReplicaRevocationConsumer, connect) -> None:
        self.consumer, self._connect = consumer, connect
        self._connection = None
        self._cursor: UUID | None = None
        self._scanning = True
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _disconnect(self) -> None:
        self.consumer.cache.unavailable()
        current, self._connection = self._connection, None
        if current is not None:
            current.close()
        self._cursor, self._scanning = None, True

    def step(self) -> bool:
        """At most128 source rows and1024 native notifications in one pass."""
        try:
            if self._connection is None:
                connection = self._connect()
                try:
                    if not connection.autocommit:
                        raise RevocationCacheUnavailable(
                            "LISTEN requires its own autocommit connection"
                        )
                    self.consumer.listener_epoch_uid = uuid4()
                    connection.execute(
                        "SELECT set_config('application_name',%s,false)",
                        ("saas-revocation-listen:" + self.consumer.listener_epoch_uid.hex,),
                    )
                    connection.execute(f"LISTEN {self.channel}")
                except BaseException:
                    connection.close()
                    raise
                self._connection = connection
                self.consumer.cache.begin_listener_epoch()
            if self._scanning:
                routes = sa.or_(
                    *(
                        sa.and_(
                            ControlPlaneOutboxEvent.aggregate_type == aggregate,
                            ControlPlaneOutboxEvent.event_type == event,
                        )
                        for aggregate, event in REVOCATION_ROUTES.values()
                    )
                )
                query = sa.select(ControlPlaneOutboxEvent.id).where(routes)
                if self._cursor is not None:
                    query = query.where(ControlPlaneOutboxEvent.id > self._cursor)
                with self.consumer.factory() as db, db.begin():
                    if db.get_bind().dialect.name == "postgresql":
                        event_ids = tuple(
                            db.scalars(
                                sa.text(
                                    "SELECT id FROM public."
                                    "saas_delivery_revocation_scan_v1(:after_id,128)"
                                ),
                                {"after_id": self._cursor},
                            )
                        )
                    else:
                        event_ids = tuple(
                            db.scalars(query.order_by(ControlPlaneOutboxEvent.id).limit(128))
                        )
                for event_id in event_ids:
                    self.consumer.consume(event_id, recovery=True)
                    self._cursor = event_id
                self._scanning = len(event_ids) == 128
            # psycopg can yield more than stop_after from a single packet. Keep a
            # hard independent cap; overflow closes the connection and rescans.
            count = 0
            notifications = self._connection.notifies(timeout=0.02, stop_after=128)
            try:
                for notification in notifications:
                    count += 1
                    if count > 1024 or notification.channel != self.channel:
                        raise RevocationCacheUnavailable(
                            "native invalidation stream exceeded its bound"
                        )
                    try:
                        event_id = UUID(notification.payload)
                    except (TypeError, ValueError, AttributeError):
                        raise RevocationCacheUnavailable(
                            "native notification reference is invalid"
                        ) from None
                    self.consumer.consume(event_id, recovery=not self.consumer.cache.ready)
            finally:
                notifications.close()
            if count >= 128:
                self.consumer.cache.unavailable()
            elif not self._scanning:
                self.consumer.cache.caught_up()
            return self.consumer.cache.ready
        except BaseException:
            self._disconnect()
            raise

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("native invalidation follower is already started")

        def follow() -> None:
            try:
                while not self._stop.is_set():
                    try:
                        self.step()
                    except Exception:  # noqa: BLE001 -- redact SQL/connection credentials
                        # No credential-bearing provider/SQL exception is logged.
                        if self.consumer.metrics is not None:
                            self.consumer.metrics.count("coverage_gap", "blocked")
                    self._stop.wait(0.2)
            finally:
                self._disconnect()

        self._thread = threading.Thread(target=follow, name="saas-revocation", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.consumer.cache.unavailable()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                raise RevocationCacheUnavailable("invalidation follower did not stop")
        else:
            self._disconnect()


class RevocationFanoutPublisher:
    """Original dispatcher may finish only after all actual listener epochs ACK.

    The native DB view is a bounded connection-lifecycle witness, not a claim of
    Kubernetes inventory. Deployment and maintenance still verify real Pod/boot
    readiness and drain fencing. Every future listener catches up all source rows.
    """

    claim_routes = tuple(OutboxClaimRoute(*route) for route in REVOCATION_ROUTES.values())

    def __init__(self, factory, *, product_revision: str) -> None:
        if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
            raise ValueError("fanout requires the exact Product revision")
        self.factory, self.product_revision = factory, product_revision

    def publish(self, *, event_id, event_type, aggregate_type, aggregate_key, payload):
        with self.factory() as db, db.begin():
            if db.get_bind().dialect.name != "postgresql":
                raise OutboxPublishError(
                    "fanout_native_witness_required", retryable=False, pre_side_effect=True
                )
            source = delivery_source(db, "revocation", event_id)
            if source is None or any(
                getattr(source, field) != value
                for field, value in (
                    ("event_type", event_type),
                    ("aggregate_type", aggregate_type),
                    ("aggregate_key", aggregate_key),
                    ("payload", payload),
                )
            ):
                raise OutboxPublishError(
                    "fanout_source_mismatch", retryable=False, pre_side_effect=True
                )
            ready = db.scalar(
                sa.text(
                    "SELECT public.saas_delivery_revocation_fanout_ready_v1("
                    ":event_id,:product_revision)"
                ),
                {"event_id": event_id, "product_revision": self.product_revision},
            )
            if ready is not True:
                raise OutboxPublishError(
                    "fanout_receivers_pending", retryable=True, pre_side_effect=True
                )
