from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError

from omnigent.db.utils import make_named_managed_session_maker, shared_read_scope
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_connections import CreateModelConnection
from saas.control_plane.model_projection import ModelCredentialProjectionPublisher
from saas.control_plane.model_routing_models import ModelProjectionTransitionRecord
from tests.saas.test_model_connections import _KEY, _fixture


@pytest.mark.parametrize("status,expected", ((200, "applied"), (409, "uncertain")))
def test_real_postgresql_projection_login_and_immutable_receipts(
    isolated_postgres_url: str, status: int, expected: str
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    worker_engine: sa.Engine | None = None
    login = f"model_projection_test_{uuid4().hex}"
    password = "isolated-projection-worker-test-only"
    quote = engine.dialect.identifier_preparer.quote
    database = sa.engine.make_url(isolated_postgres_url).database
    assert database is not None
    try:
        with engine.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            connection.exec_driver_sql(
                f"CREATE ROLE {quote(login)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                f"NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
            )
            connection.exec_driver_sql(
                f"GRANT saas_model_projection TO {quote(login)} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quote(database)} TO {quote(login)}"
            )

        service, factory, actor, cipher, _client, _headers = _fixture(engine=engine)
        operation = service.create(
            actor,
            command=CreateModelConnection("projection candidate", _KEY),
            idempotency_key="projection-login-test",
        )
        with factory() as db:
            event = db.scalar(sa.select(ControlPlaneOutboxEvent))
            assert event is not None
            envelope = {
                "event_id": event.id,
                "event_type": event.event_type,
                "aggregate_type": event.aggregate_type,
                "aggregate_key": event.aggregate_key,
                "payload": event.payload,
            }
        calls = []

        def handler(request):
            calls.append(request)
            assert worker_engine is not None
            with worker_engine.connect() as connection:
                assert (
                    connection.scalar(
                        sa.text("SELECT status FROM saas_model_projection_operations")
                    )
                    == "applying"
                )
                assert (
                    connection.scalar(
                        sa.text("SELECT count(*) FROM saas_model_projection_transitions")
                    )
                    == 1
                )
            return httpx.Response(status, json={"status": "success", "detail": _KEY})

        worker_engine = sa.create_engine(
            sa.engine.make_url(isolated_postgres_url).set(username=login, password=password)
        )
        management = LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url="https://litellm.test", management_key="isolated-management-test-secret"
            ),
            transport=httpx.MockTransport(handler),
        )
        publisher = ModelCredentialProjectionPublisher(
            worker_engine,
            secret_cipher=cipher,
            management=management,
        )
        with worker_engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT current_user")) == login
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_platform_staff_principals"))
                == 1
            )
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_platform_support_sessions"))
                == 0
            )
        for statement in (
            "UPDATE saas_model_projection_operations "
            "SET status = 'verified', version = version + 1",
            "UPDATE saas_model_projection_operations "
            "SET status = 'applying', version = version + 2",
        ):
            with pytest.raises(DBAPIError) as rejected, worker_engine.begin() as connection:
                connection.exec_driver_sql(statement)
            assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        observer = make_named_managed_session_maker(
            worker_engine, query_name_prefix="test.projection"
        )
        with shared_read_scope():
            with observer("before_external_fence") as db:
                assert (
                    db.scalar(sa.text("SELECT status FROM saas_model_projection_operations"))
                    == "requested"
                )
            publisher.publish(**envelope)
        publisher.publish(**envelope)
        assert service.operation(actor, operation.id).status == expected
        assert len(calls) == 1
        with factory() as db:
            rows = db.scalars(
                sa.select(ModelProjectionTransitionRecord).order_by(
                    ModelProjectionTransitionRecord.version
                )
            ).all()
            assert [(row.previous_status, row.status, row.version) for row in rows] == [
                ("requested", "applying", 2),
                ("applying", expected, 3),
            ]
            assert all(row.actor_principal_id == actor.principal_id for row in rows)
            assert all(row.event_id == event.id for row in rows)
            assert _KEY not in repr(rows)
        with worker_engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_model_credential_versions"))
                == 0
            )
        with pytest.raises(DBAPIError) as rejected, worker_engine.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE saas_model_projection_operations "
                "SET status = 'applying', version = version + 1"
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"

        for statement in (
            "SELECT email_normalized FROM saas_platform_staff_principals",
            "SELECT * FROM saas_tenant_memberships",
            "UPDATE saas_platform_staff_principals SET status = 'suspended'",
            "UPDATE saas_model_credential_versions SET api_key_ciphertext = 'forged'",
            "UPDATE saas_control_plane_outbox SET claimed_at = CURRENT_TIMESTAMP",
            "UPDATE saas_model_projection_operations SET request_hash = repeat('f', 64)",
            "UPDATE saas_model_projection_transitions SET status = 'verified'",
            "DELETE FROM saas_model_projection_transitions",
            "CREATE TEMP TABLE projection_forbidden (id integer)",
            "CREATE TABLE public.projection_forbidden (id integer)",
            "SET ROLE saas_secret_broker",
        ):
            with pytest.raises(DBAPIError) as rejected, worker_engine.begin() as connection:
                connection.exec_driver_sql(statement)
            assert getattr(rejected.value.orig, "sqlstate", None) == "42501", statement

        with pytest.raises(DBAPIError) as rejected, worker_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO saas_model_projection_transitions "
                    "(operation_id, version, event_id, actor_principal_id, previous_status, "
                    "status, error_code, occurred_at) VALUES "
                    "(:operation, 4, :event, :actor, 'applying', :status, NULL, CURRENT_TIMESTAMP)"
                ),
                {
                    "operation": operation.id,
                    "event": event.id,
                    "actor": actor.principal_id,
                    "status": expected,
                },
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
    finally:
        if worker_engine is not None:
            worker_engine.dispose()
        with engine.begin() as connection:
            if connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname = :login"), {"login": login}
            ):
                connection.exec_driver_sql(
                    f"REVOKE CONNECT ON DATABASE {quote(database)} FROM {quote(login)}"
                )
                connection.exec_driver_sql(f"REVOKE saas_model_projection FROM {quote(login)}")
                connection.exec_driver_sql(f"DROP ROLE {quote(login)}")
        engine.dispose()
