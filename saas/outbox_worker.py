"""Production process loop for the control-plane Outbox dispatcher."""

from __future__ import annotations

import importlib
import logging
import os
import signal
import threading
from dataclasses import dataclass
from typing import Protocol, cast

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.outbox import DispatchResult, OutboxDispatcher, OutboxPublisher
from saas.onboarding_composition import validate_production_outbox_publisher

_LOGGER = logging.getLogger("omnigent-saas-outbox")


class _Dispatcher(Protocol):
    def dispatch_once(self, *, batch_size: int = 100) -> DispatchResult: ...


class _StopSignal(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


@dataclass(frozen=True, slots=True)
class OutboxWorkerStats:
    """Aggregate counters returned after a graceful worker stop."""

    cycles: int
    claimed: int
    published: int
    event_failures: int
    infrastructure_failures: int


class OutboxWorker:
    """Drain ready events, idle efficiently, and survive transient DB failures."""

    def __init__(
        self,
        dispatcher: _Dispatcher,
        *,
        batch_size: int = 100,
        idle_interval: float = 0.5,
        error_backoff: float = 1.0,
        max_error_backoff: float = 30.0,
        logger: logging.Logger | None = None,
    ) -> None:
        if not 1 <= batch_size <= 1000:
            raise ValueError("Outbox worker batch_size must be between 1 and 1000")
        if min(idle_interval, error_backoff, max_error_backoff) <= 0:
            raise ValueError("Outbox worker intervals must be positive")
        if max_error_backoff < error_backoff:
            raise ValueError("maximum error backoff must not be smaller than initial backoff")
        self._dispatcher = dispatcher
        self._batch_size = batch_size
        self._idle_interval = idle_interval
        self._error_backoff = error_backoff
        self._max_error_backoff = max_error_backoff
        self._logger = logger or _LOGGER

    def run(self, stop: _StopSignal) -> OutboxWorkerStats:
        """Run until ``stop`` is set, returning counters for shutdown logs."""

        cycles = claimed = published = event_failures = infrastructure_failures = 0
        consecutive_errors = 0
        while not stop.is_set():
            try:
                result = self._dispatcher.dispatch_once(batch_size=self._batch_size)
            except Exception:
                infrastructure_failures += 1
                consecutive_errors += 1
                delay = min(
                    self._max_error_backoff,
                    self._error_backoff * (2 ** min(consecutive_errors - 1, 10)),
                )
                self._logger.exception(
                    "Outbox dispatch cycle failed; retrying in %.3fs",
                    delay,
                )
            else:
                cycles += 1
                claimed += result.claimed
                published += result.published
                event_failures += result.failed
                consecutive_errors = 0
                # A full batch probably means backlog remains. Drain without
                # sleeping, but yield when a partial/empty batch is observed.
                delay = 0.0 if result.claimed == self._batch_size else self._idle_interval
            if delay > 0 and stop.wait(delay):
                break
        return OutboxWorkerStats(
            cycles=cycles,
            claimed=claimed,
            published=published,
            event_failures=event_failures,
            infrastructure_failures=infrastructure_failures,
        )


def verify_dispatcher_database_role(engine: Engine) -> None:
    """Fail startup unless the connection is a non-bypass dispatcher login."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production Outbox worker requires PostgreSQL")
    with engine.connect() as connection:
        schema_facts = connection.execute(
            sa.text("SELECT current_schema(), current_schemas(false)")
        ).one()
        facts = connection.execute(
            sa.text(
                """
                SELECT current_user,
                       session_user,
                       role.rolsuper,
                       role.rolbypassrls,
                       role.rolinherit,
                       pg_has_role(current_user, 'saas_dispatcher', 'member'),
                       pg_has_role(current_user, 'saas_platform', 'member'),
                       pg_has_role(current_user, 'saas_app', 'member'),
                       pg_has_role(current_user, 'saas_authenticator', 'member'),
                       pg_has_role(current_user, 'saas_governance', 'member'),
                       pg_has_role(current_user, 'saas_executor', 'member')
                FROM pg_roles AS role
                WHERE role.rolname = current_user
                """
            )
        ).one()
        owned_tables = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                JOIN pg_roles AS owner ON owner.oid = relation.relowner
                WHERE namespace.nspname = 'public'
                  AND relation.relkind IN ('r', 'p')
                  AND relation.relname LIKE 'saas_%'
                  AND owner.rolname = current_user
                """
            )
        ).scalar_one()
        forbidden_table_privileges = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'public'
                  AND relation.relkind IN ('r', 'p')
                  AND relation.relname LIKE 'saas_%'
                  AND relation.relname <> 'saas_control_plane_outbox'
                  AND (
                      has_table_privilege(current_user, relation.oid, 'SELECT')
                      OR has_table_privilege(current_user, relation.oid, 'INSERT')
                      OR has_table_privilege(current_user, relation.oid, 'UPDATE')
                      OR has_table_privilege(current_user, relation.oid, 'DELETE')
                      OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                      OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                      OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                  )
                """
            )
        ).scalar_one()
        outbox_privileges = connection.execute(
            sa.text(
                """
                SELECT has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'SELECT'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'UPDATE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'INSERT'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'DELETE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'TRUNCATE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'TRIGGER'
                       )
                """
            )
        ).one()
    current_schema, search_path = schema_facts
    if current_schema != "public" or list(search_path) != ["public"]:
        raise RuntimeError("Outbox database login must use only the public search_path")
    (
        current_user,
        session_user,
        is_superuser,
        bypasses_rls,
        inherits_roles,
        is_dispatcher,
        is_platform,
        is_app,
        is_authenticator,
        is_governance,
        is_executor,
    ) = facts
    if current_user != session_user:
        raise RuntimeError("Outbox connection must not start under an assumed database role")
    if is_superuser or bypasses_rls or not inherits_roles:
        raise RuntimeError("Outbox database login violates the non-bypass RLS posture")
    if not is_dispatcher or any(
        (is_platform, is_app, is_authenticator, is_governance, is_executor)
    ):
        raise RuntimeError(
            "Outbox database login must have only the dispatcher privilege boundary"
        )
    if owned_tables or forbidden_table_privileges:
        raise RuntimeError("Outbox database login must not own or access non-Outbox SaaS tables")
    can_select, can_update, can_insert, can_delete, can_truncate, can_trigger = outbox_privileges
    if (
        not can_select
        or not can_update
        or any((can_insert, can_delete, can_truncate, can_trigger))
    ):
        raise RuntimeError("Outbox database login has an unsafe Outbox table grant set")


def _load_publisher(reference: str) -> OutboxPublisher:
    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        raise ValueError("publisher must use the 'module:attribute' form")
    candidate = getattr(importlib.import_module(module_name), attribute_name)
    if isinstance(candidate, type):
        publisher = candidate()
    elif callable(getattr(candidate, "publish", None)):
        publisher = candidate
    elif callable(candidate):
        publisher = candidate()
    else:
        raise TypeError("configured Outbox publisher is not an object, class, or factory")
    if not callable(getattr(publisher, "publish", None)):
        raise TypeError("configured Outbox publisher does not provide publish()")
    validate_production_outbox_publisher(cast(OutboxPublisher, publisher))
    return cast(OutboxPublisher, publisher)


def _positive_number(name: str, default: str, *, integer: bool = False) -> float | int:
    raw = os.environ.get(name, default)
    try:
        value = int(raw) if integer else float(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a number") from error
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


def main() -> int:
    """Load a publisher adapter and run one RLS-constrained worker process."""

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    database_url = os.environ.get("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL", "").strip()
    publisher_reference = os.environ.get("OMNIGENT_SAAS_OUTBOX_PUBLISHER", "").strip()
    if not database_url:
        raise RuntimeError("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL is required")
    if not publisher_reference:
        raise RuntimeError("OMNIGENT_SAAS_OUTBOX_PUBLISHER is required")

    engine = sa.create_engine(database_url, pool_pre_ping=True)
    try:
        verify_dispatcher_database_role(engine)
        sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
        dispatcher = OutboxDispatcher(sessions, _load_publisher(publisher_reference))
        stop = threading.Event()

        def _stop(_signum: int, _frame: object) -> None:
            stop.set()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        worker = OutboxWorker(
            dispatcher,
            batch_size=cast(
                int,
                _positive_number("OMNIGENT_SAAS_OUTBOX_BATCH_SIZE", "100", integer=True),
            ),
            idle_interval=cast(
                float,
                _positive_number("OMNIGENT_SAAS_OUTBOX_IDLE_SECONDS", "0.5"),
            ),
            error_backoff=cast(
                float,
                _positive_number("OMNIGENT_SAAS_OUTBOX_ERROR_BACKOFF_SECONDS", "1"),
            ),
            max_error_backoff=cast(
                float,
                _positive_number("OMNIGENT_SAAS_OUTBOX_MAX_BACKOFF_SECONDS", "30"),
            ),
        )
        stats = worker.run(stop)
        _LOGGER.info("Outbox worker stopped: %s", stats)
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
