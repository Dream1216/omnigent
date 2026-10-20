from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker

from saas.control_plane import (
    AdmissionQuotaRecord,
    ExecutionControlPlane,
    ExecutionControlPlaneError,
    RunRecord,
)
from tests.saas.test_execution_control_plane import (
    _admission_counts,
    _execution_fixture,
    _revisions,
    _task_admission,
)


def test_real_postgresql_task_run_duplicate_race_and_failed_admission_are_atomic(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    admin_engine = sa.create_engine(isolated_postgres_url)
    role = f"saas_task_admission_{uuid4().hex[:12]}"
    password = "isolated-task-admission-only"
    login_engine = None
    try:
        with admin_engine.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            connection.exec_driver_sql(
                f"CREATE ROLE {role} LOGIN PASSWORD '{password}' "
                f"NOSUPERUSER NOBYPASSRLS INHERIT; GRANT saas_app TO {role}"
            )
            connection.exec_driver_sql(
                f'GRANT CONNECT ON DATABASE "{sa.make_url(isolated_postgres_url).database}" '
                f"TO {role}"
            )
        factory, _setup_service, scope, request = _execution_fixture(admin_engine)
        login_engine = sa.create_engine(
            sa.make_url(isolated_postgres_url).set(username=role, password=password),
            pool_size=4,
            max_overflow=0,
        )
        with login_engine.connect() as connection:
            identity = connection.exec_driver_sql(
                "SELECT current_user, session_user, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname=current_user"
            ).one()
            assert identity.current_user == identity.session_user == role
            assert not identity.rolsuper and not identity.rolbypassrls
        service = ExecutionControlPlane(sessionmaker(login_engine, expire_on_commit=False))
        quota_id = service.configure_quota(
            request, project_id=scope.project_id, resource="run_units", limit_units=1
        )
        session_id = service.create_session(request, project_id=scope.project_id)
        barrier = Barrier(4)

        def admit(_index):
            barrier.wait(timeout=15)
            return _task_admission(service, scope, request, session_id)

        with ThreadPoolExecutor(max_workers=4) as pool:
            admitted = list(pool.map(admit, range(4)))
        original = next(result for result in admitted if not result.replayed)
        assert sum(not result.replayed for result in admitted) == 1
        assert all(
            result == original or result == replace(original, replayed=True) for result in admitted
        )
        counts = _admission_counts(factory)
        assert counts == {
            "saas_tasks": 1,
            "saas_session_tasks": 1,
            "saas_runs": 1,
            "saas_quota_reservations": 1,
            "saas_run_events": 2,
            "saas_control_plane_outbox": 2,
        }
        with pytest.raises(ExecutionControlPlaneError) as exhausted:
            _task_admission(service, scope, request, session_id, idempotency_key="another-message")
        assert exhausted.value.code == "quota_exceeded"
        assert _admission_counts(factory) == counts
        with pytest.raises(ExecutionControlPlaneError) as conflict:
            _task_admission(
                service, scope, request, session_id, input_payload={"message": "changed"}
            )
        assert conflict.value.code == "idempotency_conflict"
        assert _admission_counts(factory) == counts
        with factory() as db:
            quota = db.get(AdmissionQuotaRecord, quota_id)
            run = db.get(RunRecord, original.run_id)
            assert quota is not None and quota.reserved_units == 1
            assert run is not None and run.status == "queued"
            assert run.lease_owner is None and run.lease_token is None and run.fence_token == 0

        service.configure_quota(
            request, project_id=scope.project_id, resource="run_units", limit_units=2
        )
        task_id = service.create_task(request, project_id=scope.project_id, title="Existing Task")
        barrier = Barrier(4)

        def admit_existing_task(_index):
            barrier.wait(timeout=15)
            return service.admit_run(
                request,
                project_id=scope.project_id,
                task_id=task_id,
                session_id=None,
                input_payload={"prompt": "Continue the existing task"},
                quota_resource="run_units",
                quota_units=1,
                idempotency_key="existing-task-message",
                revisions=_revisions(),
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            legacy_admissions = list(pool.map(admit_existing_task, range(4)))
        assert sum(not result.replayed for result in legacy_admissions) == 1
        assert len({result.run_id for result in legacy_admissions}) == 1
        assert _admission_counts(factory) == {
            "saas_tasks": 2,
            "saas_session_tasks": 1,
            "saas_runs": 2,
            "saas_quota_reservations": 2,
            "saas_run_events": 4,
            "saas_control_plane_outbox": 4,
        }

        with login_engine.connect() as connection:
            # A pool checkout outside the authenticated request has no tenant scope.
            assert connection.exec_driver_sql("SELECT count(*) FROM saas_runs").scalar_one() == 0
    finally:
        if login_engine is not None:
            login_engine.dispose()
        with admin_engine.begin() as connection:
            if connection.execute(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": role}
            ).scalar_one_or_none():
                connection.exec_driver_sql(
                    f'REVOKE CONNECT ON DATABASE "{sa.make_url(isolated_postgres_url).database}" '
                    f"FROM {role}"
                )
                connection.exec_driver_sql(f"DROP ROLE {role}")
        admin_engine.dispose()
