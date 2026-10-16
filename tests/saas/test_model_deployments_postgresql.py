from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_connections import CreateModelConnection, ModelConnectionService
from saas.control_plane.model_deployments import ModelDeploymentService
from saas.control_plane.model_projection import ModelCredentialProjectionPublisher
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
)
from tests.saas.test_model_connections import _KEY, _Cipher, _fixture
from tests.saas.test_model_deployments import _command


def test_real_postgresql_draft_admission_and_projection_use_separate_restricted_logins(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    logins = {
        "saas_platform_app": f"draft_staff_{uuid4().hex}",
        "saas_model_projection": f"draft_projection_{uuid4().hex}",
    }
    password = "isolated-draft-login-test-only"
    quote = engine.dialect.identifier_preparer.quote
    database = sa.make_url(isolated_postgres_url).database
    assert database is not None
    restricted: dict[str, sa.Engine] = {}
    try:
        with engine.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            for role, login in logins.items():
                connection.exec_driver_sql(
                    f"CREATE ROLE {quote(login)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    f"NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
                )
                connection.exec_driver_sql(
                    f"GRANT {role} TO {quote(login)} WITH INHERIT TRUE, SET FALSE"
                )
                connection.exec_driver_sql(
                    f"GRANT CONNECT ON DATABASE {quote(database)} TO {quote(login)}"
                )
        _connections, factory, actor, cipher, _client, _headers = _fixture(engine=engine)
        for role, login in logins.items():
            restricted[role] = sa.create_engine(
                sa.make_url(isolated_postgres_url).set(username=login, password=password)
            )
        staff, worker = restricted["saas_platform_app"], restricted["saas_model_projection"]
        staff_factory = sessionmaker(staff, expire_on_commit=False)
        authorization = PlatformAuthorizationService(staff_factory)
        connections = ModelConnectionService(
            staff_factory, authorization=authorization, secret_cipher=cipher
        )
        deployments = ModelDeploymentService(staff, authorization=authorization)
        credential = connections.create(
            actor,
            command=CreateModelConnection("draft credential", _KEY),
            idempotency_key="credential-for-draft",
        )
        calls = []

        def handler(request):
            calls.append(request.url.path)
            payload = json.loads(request.content)
            if request.url.path == "/model/new":
                assert "api_key" not in payload["litellm_params"]
                assert _KEY not in request.content.decode()
                with worker.connect() as observer:
                    assert (
                        observer.scalar(
                            sa.text(
                                "SELECT status FROM saas_model_projection_operations "
                                "WHERE action = 'create_deployment'"
                            )
                        )
                        == "applying"
                    )
            return httpx.Response(200, json={"status": "success"})

        management = LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url="https://litellm.test", management_key="isolated-management-test-only"
            ),
            transport=httpx.MockTransport(handler),
        )

        def project(operation_id, *, selected_cipher):
            with factory() as db:
                event = db.scalar(
                    sa.select(ControlPlaneOutboxEvent).where(
                        ControlPlaneOutboxEvent.aggregate_key == str(operation_id)
                    )
                )
                assert event is not None
                envelope = {
                    "event_id": event.id,
                    **{
                        name: getattr(event, name)
                        for name in ("event_type", "aggregate_type", "aggregate_key", "payload")
                    },
                }
            publisher = ModelCredentialProjectionPublisher(
                worker, secret_cipher=selected_cipher, management=management
            )
            publisher.publish(**envelope)
            publisher.publish(**envelope)

        project(credential.id, selected_cipher=cipher)
        draft = replace(
            _command(),
            connection_id=credential.connection_id,
            credential_version_id=credential.credential_version_id,
        )

        def submit(_index):
            return deployments.create(actor, command=draft, idempotency_key="one-draft")

        with ThreadPoolExecutor(max_workers=2) as pool:
            operations = list(pool.map(submit, range(2)))
        assert operations[0] == operations[1]
        with pytest.raises(PlatformSecurityError) as stale:
            deployments.create(actor, command=draft, idempotency_key="stale-generation")
        assert stale.value.code == "platform_model_deployment_conflict"
        project(operations[0].id, selected_cipher=_Cipher())
        assert calls == ["/credentials", "/model/new"]
        view = deployments.list(actor)[0]
        assert view.projection_status == "applied"
        assert view.verification_status == "not_tested" and view.runtime_enabled is False
        with pytest.raises(RuntimeError, match="retained drafts"):
            with engine.begin() as connection:
                config.attributes["connection"] = connection
                command.downgrade(config, "lm1b00000001")
        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "lm1e00000001"
            )
            assert connection.scalar(
                sa.text(
                    "SELECT relforcerowsecurity FROM pg_class "
                    "WHERE oid = 'saas_model_deployment_versions'::regclass"
                )
            )
        with worker.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT current_user"))
                == logins["saas_model_projection"]
            )
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_model_deployment_versions"))
                == 0
            )
        for selected, statements in (
            (
                staff,
                (
                    "UPDATE saas_model_deployment_versions SET max_output_tokens = 64",
                    "DELETE FROM saas_model_deployment_versions",
                ),
            ),
            (
                worker,
                (
                    "SELECT display_name FROM saas_model_connections",
                    "UPDATE saas_model_deployment_versions SET max_output_tokens = 64",
                    "UPDATE saas_model_connections SET credential_generation = 9",
                    "SET ROLE saas_platform_app",
                ),
            ),
        ):
            for statement in statements:
                with pytest.raises(DBAPIError) as denied, selected.begin() as connection:
                    connection.exec_driver_sql(statement)
                assert getattr(denied.value.orig, "sqlstate", None) == "42501", statement
    finally:
        for selected in restricted.values():
            selected.dispose()
        with engine.begin() as connection:
            for role, login in logins.items():
                if connection.scalar(
                    sa.text("SELECT 1 FROM pg_roles WHERE rolname = :login"), {"login": login}
                ):
                    connection.exec_driver_sql(
                        f"REVOKE CONNECT ON DATABASE {quote(database)} FROM {quote(login)}"
                    )
                    connection.exec_driver_sql(f"REVOKE {role} FROM {quote(login)}")
                    connection.exec_driver_sql(f"DROP ROLE {quote(login)}")
        engine.dispose()
