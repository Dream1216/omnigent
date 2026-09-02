from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from saas.control_plane.outbox import DispatchResult
from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    load_production_service_role_bindings,
    render_production_service_role_bindings,
)
from saas.production.worker import (
    ProductionRunSchedulerPublisher,
    ProductionSchedulerWorker,
    ProductionWorkerAdapters,
    ProductionWorkerConfigError,
    load_production_worker_config,
)

_SOURCE_SHA = "a" * 40
_IMAGE_DIGEST = "sha256:" + "b" * 64


def _secret(path: Path, value: str) -> str:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o400)
    return str(path)


def _bindings(path: Path) -> str:
    logins = {service: f"{service}_login" for service in EXPECTED_PRODUCTION_SERVICE_ROLES}
    bindings = tuple(
        ProductionServiceRoleBinding(service, logins[service], base_role)
        for service, base_role in sorted(EXPECTED_PRODUCTION_SERVICE_ROLES.items())
    )
    path.write_text(render_production_service_role_bindings(bindings), encoding="ascii")
    path.chmod(0o400)
    return str(path)


def _receipt(path: Path, *, service_role_bindings_sha256: str) -> str:
    document = {
        "schema_version": 1,
        "status": "pass",
        "product_revision": _SOURCE_SHA,
        "official_head": "official-head",
        "saas_head": "p0s000000008",
        "database_identity_sha256": "c" * 64,
        "catalog_sha256": "d" * 64,
        "service_role_bindings_sha256": service_role_bindings_sha256,
        "runtime_rls_table_count": 12,
        "phases": ["preflight:verified", "state:verified"],
        "authorities": [
            {"kind": "principal_operator", "login": "principal_operator"},
            {"kind": "database_owner", "login": "database_owner"},
            {"kind": "official_owner", "login": "official_owner"},
            {"kind": "saas_owner", "login": "saas_owner"},
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o400)
    return str(path)


def _environment(tmp_path: Path) -> dict[str, str]:
    bindings_path = _bindings(tmp_path / "service-role-bindings.json")
    bindings = load_production_service_role_bindings(
        {"OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": bindings_path}
    )
    return {
        "OMNIGENT_SAAS_SOURCE_SHA": _SOURCE_SHA,
        "OMNIGENT_SAAS_PRODUCT_REVISION": _SOURCE_SHA,
        "OMNIGENT_SAAS_IMAGE_DIGEST": _IMAGE_DIGEST,
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": "official-head",
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": "p0s000000008",
        "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION": "1.0",
        "OMNIGENT_SAAS_DISPATCHER_DATABASE_URL_FILE": _secret(
            tmp_path / "dispatcher",
            "postgresql+psycopg://dispatcher_login:secret@db.example/omnigent"
            "?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt",
        ),
        "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE": _secret(
            tmp_path / "executor",
            "postgresql+psycopg://executor_login:secret@db.example/omnigent"
            "?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt",
        ),
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": bindings_path,
        "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE": _receipt(
            tmp_path / "receipt.json",
            service_role_bindings_sha256=bindings.sha256,
        ),
        "OMNIGENT_SAAS_WORKER_RUNNER_READINESS_FACTORY": "deployment.runner:readiness",
        "OMNIGENT_SAAS_WORKER_PREVIEW_READINESS_FACTORY": "deployment.preview:readiness",
        "OMNIGENT_SAAS_WORKER_HEALTH_STATE_FILE": str(tmp_path / "worker-health.json"),
    }


def test_worker_config_binds_exact_release_receipt_and_distinct_authorities(
    tmp_path: Path,
) -> None:
    config = load_production_worker_config(_environment(tmp_path))

    assert config.product_revision == _SOURCE_SHA
    assert config.image_digest == _IMAGE_DIGEST
    assert config.migration_receipt.product_revision == _SOURCE_SHA
    assert config.runner_adapter_factory == "deployment.runner:readiness"
    assert config.preview_adapter_factory == "deployment.preview:readiness"
    assert "secret" not in repr(config)
    assert set(config.version_document) == {
        "product_revision",
        "image_digest",
        "official_schema_revision",
        "control_plane_schema_revision",
        "adapter_contract_version",
        "service_role_bindings_sha256",
    }


@pytest.mark.parametrize(
    "name",
    [
        "DATABASE_URL",
        "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL_FILE",
    ],
)
def test_worker_config_rejects_server_owner_or_ambient_database_authority(
    tmp_path: Path,
    name: str,
) -> None:
    environ = _environment(tmp_path)
    environ[name] = "forbidden"

    with pytest.raises(ProductionWorkerConfigError, match="must not receive"):
        load_production_worker_config(environ)


def test_worker_config_rejects_product_and_source_revision_drift(tmp_path: Path) -> None:
    environ = _environment(tmp_path)
    environ["OMNIGENT_SAAS_PRODUCT_REVISION"] = "f" * 40

    with pytest.raises(ProductionWorkerConfigError, match="must match exactly"):
        load_production_worker_config(environ)


def test_worker_config_rejects_shared_or_group_readable_secret_files(tmp_path: Path) -> None:
    environ = _environment(tmp_path)
    environ["OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE"] = environ[
        "OMNIGENT_SAAS_DISPATCHER_DATABASE_URL_FILE"
    ]
    with pytest.raises(ProductionWorkerConfigError, match="distinct"):
        load_production_worker_config(environ)

    second = tmp_path / "second"
    second.mkdir()
    environ = _environment(second)
    Path(environ["OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE"]).chmod(0o440)
    with pytest.raises(ProductionWorkerConfigError, match="group or other"):
        load_production_worker_config(environ)


class _Publisher:
    def __init__(self) -> None:
        self.calls: list[tuple[UUID, dict[str, object]]] = []

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        del event_type, aggregate_type, aggregate_key
        self.calls.append((event_id, payload))


def test_run_scheduler_publisher_projects_only_queued_run_events() -> None:
    projection = _Publisher()
    fallback = _Publisher()
    publisher = ProductionRunSchedulerPublisher(projection, fallback)  # type: ignore[arg-type]
    queued_id = uuid4()
    other_id = uuid4()

    publisher.publish(
        event_id=queued_id,
        event_type="run.event.persisted",
        aggregate_type="run",
        aggregate_key=str(uuid4()),
        payload={"event_type": "run.queued"},
    )
    publisher.publish(
        event_id=other_id,
        event_type="tenant.created",
        aggregate_type="tenant",
        aggregate_key=str(uuid4()),
        payload={"event_type": "tenant.created"},
    )

    assert projection.calls == [(queued_id, {"event_type": "run.queued"})]
    assert fallback.calls == [(other_id, {"event_type": "tenant.created"})]


class _ReadyAdapter:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    def assert_production_ready(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


class _OneCycleDispatcher:
    def __init__(self, stop: threading.Event) -> None:
        self.stop = stop

    def dispatch_once(self, *, batch_size: int = 100) -> DispatchResult:
        assert batch_size == 4
        self.stop.set()
        return DispatchResult(claimed=2, published=1, failed=1, quarantined=1)


class _Recovery:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def recover_expired_dispatches(
        self,
        *,
        max_fence_token: int = 3,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        self.calls.append((max_fence_token, limit))
        return (uuid4(), uuid4())


def test_worker_runs_bounded_recovery_even_when_adapter_readiness_degrades(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stop = threading.Event()
    runner = _ReadyAdapter(error=RuntimeError("private-runner-topology"))
    preview = _ReadyAdapter()
    recovery = _Recovery()
    worker = ProductionSchedulerWorker(
        _OneCycleDispatcher(stop),
        recovery,
        ProductionWorkerAdapters(runner=runner, preview=preview),
        batch_size=4,
        idle_interval_seconds=0.001,
        error_backoff_seconds=0.001,
        max_error_backoff_seconds=0.002,
        recovery_interval_seconds=1,
        recovery_limit=7,
        max_fence_token=5,
        clock=lambda: 0.0,
    )

    with caplog.at_level(logging.ERROR, logger="omnigent-saas-production-worker"):
        stats = worker.run(stop)

    assert stats.claimed == 2
    assert stats.published == 1
    assert stats.event_failures == 1
    assert stats.quarantined == 1
    assert stats.recovery_cycles == 1
    assert stats.recovered == 2
    assert stats.adapter_readiness_failures == 1
    assert recovery.calls == [(5, 7)]
    assert runner.calls == 1
    assert preview.calls == 0
    assert "private-runner-topology" not in caplog.text


def test_worker_database_urls_are_secret_redacted_from_repr(tmp_path: Path) -> None:
    config = load_production_worker_config(_environment(tmp_path))

    assert "dispatcher_login" not in repr(config)
    assert "executor_login" not in repr(config)
    assert "secret@" not in repr(config)


def test_secret_file_helper_uses_current_process_owner(tmp_path: Path) -> None:
    environ = _environment(tmp_path)
    metadata = os.stat(environ["OMNIGENT_SAAS_DISPATCHER_DATABASE_URL_FILE"])

    assert metadata.st_uid == os.geteuid()
