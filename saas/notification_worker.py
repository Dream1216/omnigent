"""Production loop for lease-fenced notification delivery."""

from __future__ import annotations

import logging
import os
import signal
import threading
from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.notification_delivery import (
    DeliverySettlement,
    NotificationDeliveryError,
    NotificationDeliveryWorker,
)
from saas.notification_runtime import (
    build_default_notification_components,
)

_LOGGER = logging.getLogger("omnigent-saas-notification-worker")


@dataclass(frozen=True, slots=True)
class NotificationWorkerStats:
    cycles: int
    idle: int
    succeeded: int
    retries: int
    dead_lettered: int
    suppressed: int
    lease_lost: int
    infrastructure_failures: int


class NotificationWorker:
    def __init__(
        self,
        worker: NotificationDeliveryWorker,
        *,
        idle_interval: float = 0.5,
        error_backoff: float = 1.0,
        max_error_backoff: float = 30.0,
        logger: logging.Logger | None = None,
    ) -> None:
        if (
            min(idle_interval, error_backoff, max_error_backoff) <= 0
            or max_error_backoff < error_backoff
        ):
            raise ValueError("notification worker intervals are invalid")
        self._worker = worker
        self._idle_interval = idle_interval
        self._error_backoff = error_backoff
        self._max_error_backoff = max_error_backoff
        self._logger = logger or _LOGGER

    def run_once(self) -> DeliverySettlement | None:
        return self._worker.deliver_once()

    def run(self, stop: threading.Event) -> NotificationWorkerStats:
        counters = {
            "cycles": 0,
            "idle": 0,
            "succeeded": 0,
            "retries": 0,
            "dead_lettered": 0,
            "suppressed": 0,
            "lease_lost": 0,
            "infrastructure_failures": 0,
        }
        backoff = self._error_backoff
        while not stop.is_set():
            counters["cycles"] += 1
            try:
                result = self.run_once()
            except (NotificationDeliveryError, sa.exc.SQLAlchemyError):
                counters["infrastructure_failures"] += 1
                self._logger.exception(
                    "notification worker cycle failed",
                    extra={"error_code": "notification_worker_cycle_failed"},
                )
                stop.wait(backoff)
                backoff = min(self._max_error_backoff, backoff * 2)
                continue
            backoff = self._error_backoff
            if result is None:
                counters["idle"] += 1
                stop.wait(self._idle_interval)
                continue
            key = {
                "succeeded": "succeeded",
                "retry": "retries",
                "dead_letter": "dead_lettered",
                "suppressed": "suppressed",
                "lease_lost": "lease_lost",
            }[result.status]
            counters[key] += 1
        return NotificationWorkerStats(**counters)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("OMNIGENT_NOTIFICATION_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    dispatcher_url = _required_env("OMNIGENT_NOTIFICATION_DATABASE_URL")
    directory_url = _required_env("OMNIGENT_NOTIFICATION_DIRECTORY_DATABASE_URL")
    dispatcher_engine = sa.create_engine(
        dispatcher_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=0,
    )
    directory_engine = sa.create_engine(
        directory_url,
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=0,
    )
    dispatcher_sessions = sessionmaker(
        dispatcher_engine, class_=Session, expire_on_commit=False
    )
    directory_sessions = sessionmaker(
        directory_engine, class_=Session, expire_on_commit=False
    )
    components = build_default_notification_components(
        dispatcher_engine=dispatcher_engine,
        directory_engine=directory_engine,
        dispatcher_sessions=dispatcher_sessions,
        directory_sessions=directory_sessions,
        configuration={
            "workload_token_file": _required_env(
                "OMNIGENT_NOTIFICATION_WORKLOAD_TOKEN_FILE"
            ),
            "workload_issuer": _required_env(
                "OMNIGENT_NOTIFICATION_WORKLOAD_ISSUER"
            ),
            "workload_jwks_url": _required_env(
                "OMNIGENT_NOTIFICATION_WORKLOAD_JWKS_URL"
            ),
            "email_endpoint": _required_env("OMNIGENT_NOTIFICATION_EMAIL_ENDPOINT"),
            "email_bearer_token": _required_env(
                "OMNIGENT_NOTIFICATION_EMAIL_BEARER_TOKEN"
            ),
            "hmac_key_id": _required_env("OMNIGENT_NOTIFICATION_HMAC_KEY_ID"),
            "hmac_secret_b64": _required_env(
                "OMNIGENT_NOTIFICATION_HMAC_SECRET_B64"
            ),
            "previous_hmac_keys_json": os.environ.get(
                "OMNIGENT_NOTIFICATION_PREVIOUS_HMAC_KEYS_JSON", "[]"
            ),
        },
    )
    delivery_worker = NotificationDeliveryWorker(
        components.authority,
        components.identity_provider,
        components.recipient_resolver,
        components.context_resolver,
        components.catalog,
        components.provider,
    )
    worker = NotificationWorker(
        delivery_worker,
        idle_interval=_positive_env("OMNIGENT_NOTIFICATION_IDLE_SECONDS", 0.5),
        error_backoff=_positive_env("OMNIGENT_NOTIFICATION_ERROR_BACKOFF_SECONDS", 1.0),
        max_error_backoff=_positive_env(
            "OMNIGENT_NOTIFICATION_MAX_ERROR_BACKOFF_SECONDS", 30.0
        ),
    )
    stop = threading.Event()

    def stop_worker(signum: int, frame: object) -> None:
        del signum, frame
        stop.set()

    signal.signal(signal.SIGINT, stop_worker)
    signal.signal(signal.SIGTERM, stop_worker)
    worker.run(stop)
    return 0


def _required_env(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(f"{key} is required")
    return value


def _positive_env(key: str, default: float) -> float:
    raw = os.environ.get(key)
    try:
        value = default if raw is None else float(raw)
    except ValueError as error:
        raise RuntimeError(f"{key} must be a number") from error
    if value <= 0:
        raise RuntimeError(f"{key} must be positive")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
