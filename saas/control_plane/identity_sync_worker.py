"""Bounded independent claim/read/apply loops with content-free health counters."""

from __future__ import annotations

import threading
import time
from datetime import datetime

import sqlalchemy as sa

from saas.control_plane.db_models import GlobalUser, IdentityConnection
from saas.control_plane.identity_event_models import (
    IdentityEventInboxRecord,
    IdentityProviderStateRecord,
)
from saas.control_plane.identity_inbox import _stored, _utc
from saas.control_plane.identity_sync import IdentityStateSyncService


class IdentitySyncWorker:
    def __init__(
        self, service: IdentityStateSyncService, *, concurrency: int = 4, poll_seconds: int = 1
    ):
        if (
            type(concurrency) is not int
            or not 1 <= concurrency <= 16
            or type(poll_seconds) is not int
            or not 1 <= poll_seconds <= 5
        ):
            raise ValueError("identity worker capacity is invalid")
        self.service, self.concurrency, self.poll_seconds = service, concurrency, poll_seconds
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._heartbeats = [0.0] * concurrency
        self._counts = {"reconciled_total": 0, "events_total": 0, "failures_total": 0}

    def start(self) -> None:
        with self._lock:
            if self._threads or self._stop.is_set():
                raise RuntimeError("identity worker lifecycle already started")
            self._heartbeats = [time.monotonic()] * self.concurrency
            self._threads = [
                threading.Thread(
                    target=self._run, args=(i,), name=f"identity-sync-{i}", daemon=True
                )
                for i in range(self.concurrency)
            ]
            for thread in self._threads:
                thread.start()

    def stop(self, *, timeout_seconds: float = 10) -> None:
        self._stop.set()
        deadline = time.monotonic() + timeout_seconds
        for thread in self._threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in self._threads):
            raise RuntimeError("identity worker shutdown timed out")

    def healthy(self) -> bool:
        with self._lock:
            return (
                bool(self._threads)
                and not self._stop.is_set()
                and all(
                    thread.is_alive() and time.monotonic() - self._heartbeats[i] <= 60
                    for i, thread in enumerate(self._threads)
                )
            )

    def _beat(self, index: int) -> None:
        with self._lock:
            self._heartbeats[index] = time.monotonic()

    def _count(self, key: str) -> None:
        with self._lock:
            self._counts[key] += 1

    def _periodic(self) -> bool:
        try:
            claim = self.service.claim_due()
            if claim is None:
                return False
            self.service.process(claim)
            self._count("reconciled_total")
            return True
        except Exception:  # noqa: BLE001 - no exception messages or locators enter metrics.
            self._count("failures_total")
            return False

    def _event(self) -> bool:
        try:
            processed = self.service.process_next_event()
            if processed:
                self._count("events_total")
            return processed
        except Exception:  # noqa: BLE001 - account work cannot prevent durable event retries.
            self._count("failures_total")
            return False

    def _run(self, index: int) -> None:
        while not self._stop.is_set():
            self._beat(index)
            periodic = self._periodic()
            self._beat(index)
            event = False if self._stop.is_set() else self._event()
            self._beat(index)
            if not periodic and not event:
                self._stop.wait(self.poll_seconds)

    def snapshot(self, *, now: datetime | None = None) -> dict[str, int | float]:
        checked = _utc(now)
        policy = self.service.policy
        with self.service._sessions() as db:
            provider_count, oldest_provider, missing_count, failure_count = db.execute(
                sa.select(
                    sa.func.count(IdentityConnection.id),
                    sa.func.min(
                        sa.func.coalesce(
                            IdentityProviderStateRecord.checked_at, IdentityConnection.created_at
                        )
                    ),
                    sa.func.coalesce(
                        sa.func.sum(
                            sa.case((IdentityProviderStateRecord.checked_at.is_(None), 1), else_=0)
                        ),
                        0,
                    ),
                    sa.func.coalesce(
                        sa.func.sum(
                            sa.case(
                                (IdentityProviderStateRecord.last_error_code.is_not(None), 1),
                                else_=0,
                            )
                        ),
                        0,
                    ),
                )
                .join(GlobalUser, GlobalUser.id == IdentityConnection.user_id)
                .outerjoin(
                    IdentityProviderStateRecord,
                    IdentityProviderStateRecord.connection_id == IdentityConnection.id,
                )
                .where(
                    GlobalUser.status == "active",
                    IdentityConnection.status == "active",
                    IdentityConnection.provider == "casdoor",
                    IdentityConnection.issuer == policy.issuer,
                    sa.or_(
                        IdentityProviderStateRecord.connection_id.is_(None),
                        IdentityProviderStateRecord.status != "deleted",
                    ),
                )
            ).one()
            backlog, oldest_event, dead = db.execute(
                sa.select(
                    sa.func.coalesce(
                        sa.func.sum(
                            sa.case((IdentityEventInboxRecord.status != "dead", 1), else_=0)
                        ),
                        0,
                    ),
                    sa.func.min(
                        sa.case(
                            (
                                IdentityEventInboxRecord.status != "dead",
                                IdentityEventInboxRecord.received_at,
                            ),
                            else_=None,
                        )
                    ),
                    sa.func.coalesce(
                        sa.func.sum(
                            sa.case((IdentityEventInboxRecord.status == "dead", 1), else_=0)
                        ),
                        0,
                    ),
                ).where(
                    IdentityEventInboxRecord.issuer == policy.issuer,
                    IdentityEventInboxRecord.organization == policy.organization,
                    IdentityEventInboxRecord.status.in_(
                        ("pending", "processing", "retry", "dead")
                    ),
                )
            ).one()
        with self._lock:
            counts = dict(self._counts)

        def age(value):
            return (
                max(0.0, (checked - _stored(value)).total_seconds()) if value is not None else 0.0
            )

        return {
            **counts,
            "connections": provider_count,
            "unchecked_connections": missing_count,
            "readback_failed_connections": failure_count,
            "reconcile_age_seconds": age(oldest_provider),
            "event_backlog": backlog,
            "event_age_seconds": age(oldest_event),
            "dead_events_total": dead,
        }
