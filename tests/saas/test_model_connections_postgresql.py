from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_connections import CreateModelConnection, ModelConnectionService
from saas.control_plane.model_routing_models import (
    ModelCredentialVersionRecord,
    ModelProjectionOperationRecord,
)
from saas.control_plane.platform_security import PlatformAuthorizationService
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context
from tests.saas.test_model_connections import _KEY, _fixture


def test_real_postgresql_projection_admission_and_append_only_credentials(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    try:
        with engine.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
        _service, factory, actor, cipher, _client, _headers = _fixture(engine=engine)

        class StaffSession(Session):
            pass

        @sa.event.listens_for(StaffSession, "after_begin")
        def bind_staff_role(_session, _transaction, connection):
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform_app")

        staff_factory = sessionmaker(engine, class_=StaffSession, expire_on_commit=False)
        service = ModelConnectionService(
            staff_factory,
            authorization=PlatformAuthorizationService(staff_factory),
            secret_cipher=cipher,
        )

        def submit(_index):
            return service.create(
                actor,
                command=CreateModelConnection("candidate", _KEY),
                idempotency_key="concurrent-identical-command",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            receipts = list(executor.map(submit, range(2)))
        assert receipts[0] == receipts[1]
        assert receipts[0].status == "requested"
        with factory() as db:
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(ModelProjectionOperationRecord))
                == 1
            )
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(ModelCredentialVersionRecord))
                == 1
            )
            assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 1

        for table, values in (
            (ModelCredentialVersionRecord, {"api_key_ciphertext": "replacement-is-not-allowed"}),
            (ModelProjectionOperationRecord, {"status": "verified"}),
        ):
            with pytest.raises(DBAPIError) as error:
                with staff_factory.begin() as db:
                    apply_platform_rls_context(
                        db, PlatformRlsContext(principal_id=actor.principal_id)
                    )
                    db.execute(sa.update(table).values(**values))
            assert getattr(error.value.orig, "sqlstate", None) == "42501"

        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform_app")
            assert connection.scalar(sa.text("SELECT count(*) FROM saas_model_connections")) == 0
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_model_credential_versions"))
                == 0
            )

        with pytest.raises(DBAPIError) as error:
            with staff_factory.begin() as db:
                apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))
                db.add(
                    ControlPlaneOutboxEvent(
                        id=uuid4(),
                        tenant_id=None,
                        aggregate_type="platform_model",
                        aggregate_key=str(receipts[0].id),
                        event_type="platform.model_projection.requested",
                        idempotency_key="forged-payload",
                        request_hash="a" * 64,
                        payload={
                            "event_type": "platform.model_projection.requested",
                            "schema_version": 1,
                            "operation_id": str(receipts[0].id),
                            "credential_version_id": str(receipts[0].credential_version_id),
                            "api_key": "forbidden-event-secret",
                        },
                    )
                )
        assert getattr(error.value.orig, "sqlstate", None) == "42501"

        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_app")
            with pytest.raises(DBAPIError) as error:
                connection.exec_driver_sql("SELECT * FROM saas_model_connections")
            assert getattr(error.value.orig, "sqlstate", None) == "42501"
    finally:
        engine.dispose()
