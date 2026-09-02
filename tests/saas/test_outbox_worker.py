from __future__ import annotations

import logging
import threading
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from saas.control_plane.onboarding import OnboardingOutboxPublisher
from saas.control_plane.outbox import DispatchResult
from saas.outbox_worker import OutboxWorker, _load_dispatcher_database_url, _load_publisher


class _Publisher:
    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        del event_id, event_type, aggregate_type, aggregate_key, payload


class _ValidatedPublisher(_Publisher):
    def __init__(self) -> None:
        self.validated = False

    def validate_outbox_configuration(self) -> None:
        self.validated = True


class _ScriptedDispatcher:
    def __init__(
        self,
        stop: threading.Event,
        outcomes: list[DispatchResult | Exception],
    ) -> None:
        self.stop = stop
        self.outcomes = outcomes
        self.batch_sizes: list[int] = []

    def dispatch_once(self, *, batch_size: int = 100) -> DispatchResult:
        self.batch_sizes.append(batch_size)
        outcome = self.outcomes.pop(0)
        if not self.outcomes:
            self.stop.set()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_worker_drains_full_batches_and_returns_shutdown_counters() -> None:
    stop = threading.Event()
    dispatcher = _ScriptedDispatcher(
        stop,
        [
            DispatchResult(claimed=2, published=1, failed=1, quarantined=1),
            DispatchResult(claimed=1, published=1, failed=0),
        ],
    )
    worker = OutboxWorker(dispatcher, batch_size=2, idle_interval=0.001)

    stats = worker.run(stop)

    assert dispatcher.batch_sizes == [2, 2]
    assert stats.cycles == 2
    assert stats.claimed == 3
    assert stats.published == 2
    assert stats.event_failures == 1
    assert stats.quarantined == 1
    assert stats.infrastructure_failures == 0


def test_worker_survives_transient_dispatch_infrastructure_failure() -> None:
    stop = threading.Event()
    dispatcher = _ScriptedDispatcher(
        stop,
        [RuntimeError("database temporarily unavailable"), DispatchResult(0, 0, 0)],
    )
    worker = OutboxWorker(
        dispatcher,
        batch_size=10,
        idle_interval=0.001,
        error_backoff=0.001,
        max_error_backoff=0.002,
    )

    stats = worker.run(stop)

    assert dispatcher.batch_sizes == [10, 10]
    assert stats.cycles == 1
    assert stats.quarantined == 0
    assert stats.infrastructure_failures == 1


def test_worker_logs_content_blind_infrastructure_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stop = threading.Event()
    dispatcher = _ScriptedDispatcher(
        stop,
        [RuntimeError("provider-secret-value"), DispatchResult(0, 0, 0)],
    )
    worker = OutboxWorker(
        dispatcher,
        batch_size=10,
        idle_interval=0.001,
        error_backoff=0.001,
        max_error_backoff=0.002,
    )

    with caplog.at_level(logging.ERROR, logger="saas.outbox_worker"):
        stats = worker.run(stop)

    assert stats.infrastructure_failures == 1
    assert "Outbox dispatch cycle failed" in caplog.text
    assert "provider-secret-value" not in caplog.text


@pytest.mark.parametrize(
    "candidate",
    [_Publisher, _Publisher(), lambda: _Publisher()],
)
def test_publisher_loader_accepts_class_instance_and_factory(
    monkeypatch: pytest.MonkeyPatch,
    candidate: object,
) -> None:
    monkeypatch.setattr(
        "saas.outbox_worker.importlib.import_module",
        lambda _module: SimpleNamespace(candidate=candidate),
    )

    assert isinstance(_load_publisher("publisher_module:candidate"), _Publisher)


def test_publisher_loader_runs_supported_composition_startup_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _ValidatedPublisher()
    monkeypatch.setattr(
        "saas.outbox_worker.importlib.import_module",
        lambda _module: SimpleNamespace(candidate=candidate),
    )

    assert _load_publisher("publisher_module:candidate") is candidate
    assert candidate.validated


def test_publisher_loader_rejects_raw_optional_onboarding_publisher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = object.__new__(OnboardingOutboxPublisher)
    monkeypatch.setattr(
        "saas.outbox_worker.importlib.import_module",
        lambda _module: SimpleNamespace(candidate=candidate),
    )

    with pytest.raises(RuntimeError, match="create_tenant_onboarding_composition"):
        _load_publisher("publisher_module:candidate")


def test_dispatcher_database_url_can_be_loaded_from_owner_only_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "dispatcher-dsn"
    path.write_text("postgresql+psycopg://dispatcher:secret@db.example.test/saas\n")
    path.chmod(0o400)
    monkeypatch.delenv("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL", raising=False)
    monkeypatch.setenv("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL_FILE", str(path))

    assert _load_dispatcher_database_url().startswith("postgresql+psycopg://dispatcher:")


def test_dispatcher_database_url_rejects_ambiguous_or_unsafe_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "dispatcher-dsn"
    path.write_text("postgresql+psycopg://dispatcher:secret@db.example.test/saas\n")
    path.chmod(0o600)
    monkeypatch.setenv("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL_FILE", str(path))
    monkeypatch.delenv("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="unsafe"):
        _load_dispatcher_database_url()

    path.chmod(0o400)
    monkeypatch.setenv(
        "OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL",
        "postgresql+psycopg://dispatcher:other@db.example.test/saas",
    )
    with pytest.raises(RuntimeError, match="exactly one"):
        _load_dispatcher_database_url()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"batch_size": 0},
        {"idle_interval": 0},
        {"error_backoff": 2, "max_error_backoff": 1},
    ],
)
def test_worker_rejects_unsafe_poll_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        OutboxWorker(_ScriptedDispatcher(threading.Event(), []), **kwargs)
