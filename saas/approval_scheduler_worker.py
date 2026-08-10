"""Production loop for approval reconciliation, reminder, escalation, and expiry."""

from __future__ import annotations

import importlib
import json
import logging
import os
import signal
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, cast

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.approval_operations import (
    ApprovalOperationsError,
    ApprovalProjectionService,
)
from saas.control_plane.approval_scheduler import (
    ApprovalScheduler,
    ApprovalSchedulerRunResult,
    ApprovalSchedulerSource,
)
from saas.control_plane.notification_delivery import (
    NotificationDeliveryError,
    NotificationDeliveryService,
)
from saas.notification_runtime import notification_digesters

_LOGGER = logging.getLogger("omnigent-saas-approval-scheduler")
_DEFAULT_SOURCE_FACTORY = (
    "saas.control_plane.approval_source_adapters:"
    "production_approval_scheduler_source_factory"
)
_SOURCE_KINDS = frozenset(
    {"enterprise", "privacy", "audit", "support.customer", "support.staff"}
)
_SOURCE_ROLE_NAMES = {
    "enterprise": "saas_approval_scheduler_enterprise",
    "privacy": "saas_approval_scheduler_privacy",
    "audit": "saas_approval_scheduler_audit",
    "support.customer": "saas_approval_scheduler_support_customer",
    "support.staff": "saas_approval_scheduler_support_staff",
}
_SOURCE_DATABASE_ENV = {
    "enterprise": "OMNIGENT_APPROVAL_SCHEDULER_ENTERPRISE_DATABASE_URL",
    "privacy": "OMNIGENT_APPROVAL_SCHEDULER_PRIVACY_DATABASE_URL",
    "audit": "OMNIGENT_APPROVAL_SCHEDULER_AUDIT_DATABASE_URL",
    "support.customer": "OMNIGENT_APPROVAL_SCHEDULER_SUPPORT_CUSTOMER_DATABASE_URL",
    "support.staff": "OMNIGENT_APPROVAL_SCHEDULER_SUPPORT_STAFF_DATABASE_URL",
}


@dataclass(frozen=True, slots=True)
class ApprovalSchedulerSourceFactoryContext:
    """Verified database-bound dependencies supplied to the production factory."""

    sessions: sessionmaker[Session] = field(repr=False)
    source_sessions: Mapping[str, sessionmaker[Session]] = field(repr=False)
    projection: ApprovalProjectionService
    notifications: NotificationDeliveryService
    configuration: Mapping[str, str] = field(repr=False)


class ApprovalSchedulerSourceFactory(Protocol):
    def __call__(
        self, context: ApprovalSchedulerSourceFactoryContext
    ) -> dict[str, ApprovalSchedulerSource]: ...


@dataclass(frozen=True, slots=True)
class ApprovalSchedulerWorkerStats:
    cycles: int
    reconciled_pending: int
    reconciled_terminal: int
    reminded: int
    escalated: int
    expired: int
    item_failures: int
    infrastructure_failures: int


class ApprovalSchedulerWorker:
    def __init__(
        self,
        scheduler: ApprovalScheduler,
        *,
        interval: float = 15.0,
        error_backoff: float = 1.0,
        max_error_backoff: float = 30.0,
        limit: int = 100,
        logger: logging.Logger | None = None,
    ) -> None:
        if (
            min(interval, error_backoff, max_error_backoff) <= 0
            or max_error_backoff < error_backoff
            or not 1 <= limit <= 500
        ):
            raise ValueError("approval scheduler worker configuration is invalid")
        self._scheduler = scheduler
        self._interval = interval
        self._error_backoff = error_backoff
        self._max_error_backoff = max_error_backoff
        self._limit = limit
        self._logger = logger or _LOGGER

    def run_once(self) -> ApprovalSchedulerRunResult:
        return self._scheduler.run_once(limit=self._limit)

    def run(self, stop: threading.Event) -> ApprovalSchedulerWorkerStats:
        counters = {
            "cycles": 0,
            "reconciled_pending": 0,
            "reconciled_terminal": 0,
            "reminded": 0,
            "escalated": 0,
            "expired": 0,
            "item_failures": 0,
            "infrastructure_failures": 0,
        }
        backoff = self._error_backoff
        while not stop.is_set():
            counters["cycles"] += 1
            try:
                result = self.run_once()
            except (
                ApprovalOperationsError,
                NotificationDeliveryError,
                sa.exc.SQLAlchemyError,
            ):
                counters["infrastructure_failures"] += 1
                self._logger.exception(
                    "approval scheduler cycle failed",
                    extra={"error_code": "approval_scheduler_cycle_failed"},
                )
                stop.wait(backoff)
                backoff = min(self._max_error_backoff, backoff * 2)
                continue
            backoff = self._error_backoff
            counters["reconciled_pending"] += result.reconciled_pending
            counters["reconciled_terminal"] += result.reconciled_terminal
            counters["reminded"] += result.reminded
            counters["escalated"] += result.escalated
            counters["expired"] += result.expired
            counters["item_failures"] += result.failed
            stop.wait(self._interval)
        return ApprovalSchedulerWorkerStats(**counters)


def build_approval_scheduler(
    *,
    sessions: sessionmaker[Session],
    source_sessions: Mapping[str, sessionmaker[Session]],
    source_factory: ApprovalSchedulerSourceFactory,
    configuration: Mapping[str, str],
) -> ApprovalScheduler:
    if set(source_sessions) != _SOURCE_KINDS:
        raise RuntimeError("approval scheduler source session registry is incomplete")
    current, previous = notification_digesters(
        {
            "hmac_key_id": _required(configuration, "hmac_key_id"),
            "hmac_secret_b64": _required(configuration, "hmac_secret_b64"),
            "previous_hmac_keys_json": configuration.get(
                "previous_hmac_keys_json", "[]"
            ),
        }
    )
    projection = ApprovalProjectionService()
    notifications = NotificationDeliveryService(
        sessions,
        digester=current,
        previous_digesters=previous,
    )
    context = ApprovalSchedulerSourceFactoryContext(
        sessions=sessions,
        source_sessions=source_sessions,
        projection=projection,
        notifications=notifications,
        configuration=configuration,
    )
    sources = source_factory(context)
    if not isinstance(sources, dict) or set(sources) != _SOURCE_KINDS:
        raise RuntimeError("approval scheduler source registry is incomplete")
    return ApprovalScheduler(
        sessions,
        projection=projection,
        sources=sources,
        notifications=notifications,
    )


def load_approval_scheduler_source_factory(
    value: str,
) -> ApprovalSchedulerSourceFactory:
    module_name, separator, attribute_name = value.strip().partition(":")
    if (
        not separator
        or not module_name
        or not attribute_name
        or not all(part.isidentifier() for part in module_name.split("."))
        or not attribute_name.isidentifier()
    ):
        raise RuntimeError("approval scheduler source factory path is invalid")
    try:
        module = importlib.import_module(module_name)
        candidate = getattr(module, attribute_name)
    except (ImportError, AttributeError) as error:
        raise RuntimeError("approval scheduler source factory is unavailable") from error
    if not callable(candidate):
        raise RuntimeError("approval scheduler source factory is not callable")
    return cast(ApprovalSchedulerSourceFactory, candidate)


def verify_approval_scheduler_database_role(engine: Engine) -> None:
    """Fail startup unless the login has only scheduler notification authority."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production approval scheduler requires PostgreSQL")
    with engine.connect() as connection:
        facts = connection.execute(
            sa.text(
                "SELECT current_user, role.rolsuper, role.rolbypassrls, "
                "pg_has_role(current_user, 'saas_notification_scheduler', 'member'), "
                "pg_has_role(current_user, 'saas_notification_dispatcher', 'member'), "
                "pg_has_role(current_user, 'saas_notification_directory', 'member'), "
                "pg_has_role(current_user, 'saas_platform_governance', 'member'), "
                "pg_has_role(current_user, 'saas_governance', 'member'), "
                "pg_has_role(current_user, 'saas_platform', 'member') "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
    if facts[1] or facts[2] or not facts[3] or any(
        facts[index] for index in (4, 5, 6, 7, 8)
    ):
        raise RuntimeError("approval scheduler database role boundary is invalid")


def verify_approval_source_scheduler_database_role(
    engine: Engine, *, source_kind: str
) -> None:
    """Require one exact source authority role and reject cross-source authority."""

    expected_role = _SOURCE_ROLE_NAMES.get(source_kind)
    if expected_role is None:
        raise RuntimeError("approval scheduler source kind is invalid")
    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production approval source scheduler requires PostgreSQL")
    role_names = tuple(_SOURCE_ROLE_NAMES.values())
    with engine.connect() as connection:
        login = connection.execute(
            sa.text(
                "SELECT role.rolsuper, role.rolbypassrls, "
                "pg_has_role(current_user, 'saas_notification_scheduler', 'member'), "
                "pg_has_role(current_user, 'saas_notification_dispatcher', 'member'), "
                "pg_has_role(current_user, 'saas_notification_directory', 'member'), "
                "pg_has_role(current_user, 'saas_platform_governance', 'member'), "
                "pg_has_role(current_user, 'saas_governance', 'member'), "
                "pg_has_role(current_user, 'saas_platform', 'member') "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
        memberships = frozenset(
            connection.execute(
                sa.text(
                    "SELECT candidate.rolname FROM pg_roles AS candidate "
                    "WHERE candidate.rolname = ANY(:role_names) "
                    "AND pg_has_role(current_user, candidate.rolname, 'member')"
                ),
                {"role_names": list(role_names)},
            ).scalars()
        )
    if login[0] or login[1] or any(login[index] for index in range(2, 8)):
        raise RuntimeError("approval source scheduler database role boundary is invalid")
    if memberships != {expected_role}:
        raise RuntimeError("approval source scheduler database role boundary is invalid")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("OMNIGENT_APPROVAL_SCHEDULER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    engine = sa.create_engine(
        _required_env("OMNIGENT_APPROVAL_SCHEDULER_DATABASE_URL"),
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=0,
    )
    source_engines: dict[str, Engine] = {}
    try:
        verify_approval_scheduler_database_role(engine)
        sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
        source_sessions: dict[str, sessionmaker[Session]] = {}
        for source_kind, environment_key in _SOURCE_DATABASE_ENV.items():
            source_engine = sa.create_engine(
                _required_env(environment_key),
                pool_pre_ping=True,
                pool_size=1,
                max_overflow=0,
            )
            source_engines[source_kind] = source_engine
            verify_approval_source_scheduler_database_role(
                source_engine, source_kind=source_kind
            )
            source_sessions[source_kind] = sessionmaker(
                source_engine, class_=Session, expire_on_commit=False
            )
        configuration = {
            "hmac_key_id": _required_env("OMNIGENT_NOTIFICATION_HMAC_KEY_ID"),
            "hmac_secret_b64": _required_env(
                "OMNIGENT_NOTIFICATION_HMAC_SECRET_B64"
            ),
            "previous_hmac_keys_json": os.environ.get(
                "OMNIGENT_NOTIFICATION_PREVIOUS_HMAC_KEYS_JSON", "[]"
            ),
            **_source_configuration(
                os.environ.get("OMNIGENT_APPROVAL_SCHEDULER_SOURCE_CONFIG_JSON", "{}")
            ),
        }
        source_factory = load_approval_scheduler_source_factory(
            os.environ.get(
                "OMNIGENT_APPROVAL_SCHEDULER_SOURCE_FACTORY",
                _DEFAULT_SOURCE_FACTORY,
            )
        )
        scheduler = build_approval_scheduler(
            sessions=sessions,
            source_sessions=source_sessions,
            source_factory=source_factory,
            configuration=configuration,
        )
        worker = ApprovalSchedulerWorker(
            scheduler,
            interval=_positive_env("OMNIGENT_APPROVAL_SCHEDULER_INTERVAL_SECONDS", 15.0),
            error_backoff=_positive_env(
                "OMNIGENT_APPROVAL_SCHEDULER_ERROR_BACKOFF_SECONDS", 1.0
            ),
            max_error_backoff=_positive_env(
                "OMNIGENT_APPROVAL_SCHEDULER_MAX_ERROR_BACKOFF_SECONDS", 30.0
            ),
            limit=_integer_env("OMNIGENT_APPROVAL_SCHEDULER_BATCH_LIMIT", 100),
        )
        stop = threading.Event()

        def stop_worker(signum: int, frame: object) -> None:
            del signum, frame
            stop.set()

        signal.signal(signal.SIGINT, stop_worker)
        signal.signal(signal.SIGTERM, stop_worker)
        worker.run(stop)
        return 0
    finally:
        for source_engine in source_engines.values():
            source_engine.dispose()
        engine.dispose()


def _source_configuration(raw: str) -> dict[str, str]:
    if len(raw) > 65_536:
        raise RuntimeError("approval scheduler source configuration is too large")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("approval scheduler source configuration is invalid") from error
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise RuntimeError("approval scheduler source configuration is invalid")
    return value


def _required(values: Mapping[str, str], key: str) -> str:
    value = values.get(key, "").strip()
    if not value:
        raise RuntimeError(f"approval scheduler configuration {key} is required")
    return value


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


def _integer_env(key: str, default: int) -> int:
    raw = os.environ.get(key)
    try:
        value = default if raw is None else int(raw)
    except ValueError as error:
        raise RuntimeError(f"{key} must be an integer") from error
    if not 1 <= value <= 500:
        raise RuntimeError(f"{key} must be between 1 and 500")
    return value


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ApprovalSchedulerSourceFactoryContext",
    "ApprovalSchedulerWorker",
    "ApprovalSchedulerWorkerStats",
    "build_approval_scheduler",
    "load_approval_scheduler_source_factory",
    "main",
    "verify_approval_scheduler_database_role",
    "verify_approval_source_scheduler_database_role",
]
