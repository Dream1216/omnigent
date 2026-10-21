from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker

from saas.control_plane import model_publications
from saas.control_plane.model_document_storage import decode_model_document, encode_model_document
from saas.control_plane.model_publications import ModelPublicationService
from saas.control_plane.model_routing_models import ModelPublicationDisablementRecord
from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.platform_security import PlatformAuthorizationService
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context
from saas.control_plane.tenant_model_catalog import TenantModelCatalog
from tests.saas import test_model_projection
from tests.saas.test_agent_catalog import _runtime
from tests.saas.test_model_connections import _fixture as _connection_fixture
from tests.saas.test_model_publications import _envelope, _fixture
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


def test_real_postgresql_rejects_a_future_replica_proof_without_publication(
    priced_execution, monkeypatch
):
    f = priced_execution
    monkeypatch.setattr(
        test_model_projection, "_fixture", lambda: _connection_fixture(engine=f.engine)
    )
    source, publisher, factory, actor, request, calls = _fixture()
    request["tenant_id"] = f.scope.tenant_id
    operation = source.admit(actor, **request)
    before = list(calls)
    changed = []

    def future_proof(connection, _cursor, statement, parameters, _context, _many):
        if not statement.startswith("INSERT INTO saas_model_publication_versions "):
            return
        raw = parameters["canonical_readiness"]
        document = json.loads(decode_model_document(raw if isinstance(raw, bytes) else raw.obj))
        at = connection.scalar(sa.select(sa.func.clock_timestamp())) + timedelta(seconds=5)
        document["completed_at"] = at.isoformat()
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        parameters["canonical_readiness"] = encode_model_document(canonical)
        parameters["readiness_sha256"] = sha256(canonical.encode("ascii")).hexdigest()
        changed.append(True)

    sa.event.listen(f.engine, "before_cursor_execute", future_proof)
    try:
        with pytest.raises(OutboxPublishError, match="model_publication_storage_unavailable"):
            publisher.publish(**_envelope(factory, operation.id))
    finally:
        sa.event.remove(f.engine, "before_cursor_execute", future_proof)
    assert changed == [True]
    assert source.list(actor) == ()
    assert calls == before


def test_real_staff_disablement_and_customer_column_authority(
    priced_execution, monkeypatch, record_property
):
    f = priced_execution
    monkeypatch.setattr(
        test_model_projection, "_fixture", lambda: _connection_fixture(engine=f.engine)
    )
    source, publisher, factory, actor, request, calls = _fixture()
    request["tenant_id"] = f.scope.tenant_id
    operation = source.admit(actor, **request)
    publisher.publish(**_envelope(factory, operation.id))
    publication = source.list(actor)[0]
    runtime = replace(
        _runtime(),
        actor_id=f.scope.owner_id,
        tenant_id=f.scope.tenant_id,
        space_id=f.scope.space_id,
        project_id=f.scope.project_id,
    )
    customer = TenantModelCatalog(f.app)
    assert len(customer.list(runtime)) == 1
    role = "disable_staff_" + uuid4().hex
    staff = None
    created = False
    try:
        with f.engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {role} LOGIN PASSWORD 'isolated-disable-only' "
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
            )
            connection.exec_driver_sql(
                f"GRANT saas_platform_app TO {role} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f'GRANT CONNECT ON DATABASE "{f.engine.url.database}" TO {role}'
            )
        created = True
        staff = sa.create_engine(f.engine.url.set(username=role, password="isolated-disable-only"))
        sessions = sessionmaker(staff, expire_on_commit=False)
        service = ModelPublicationService(
            staff, authorization=PlatformAuthorizationService(sessions), pricing=source._pricing
        )
        before = list(calls)
        args = {
            "publication_id": publication.id,
            "expected_generation": 1,
            "idempotency_key": "disable-real-staff-001",
        }

        class AheadClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return super().now(tz) + timedelta(seconds=3)

        with monkeypatch.context() as clock:
            clock.setattr(model_publications, "datetime", AheadClock)
            result = service.disable(actor, **args)
            assert service.disable(actor, **args) == result
        assert service.find_disablement(actor, idempotency_key=args["idempotency_key"]) == result
        assert service.disablement_receipt(actor, result["disablement_id"]) == result
        assert service.find_disablement(actor, idempotency_key="unknown-command-001") is None
        assert service.list(actor)[0].disabled is True
        assert service.receipt(actor, publication.operation_id)["publication"]["disabled"] is True
        assert result["created_at"] <= datetime.now(timezone.utc)
        assert customer.list(runtime) == []
        assert calls == before
        with pytest.raises(sa.exc.DBAPIError, match="permission denied"):
            with staff.connect() as connection:
                connection.exec_driver_sql(
                    "SELECT token_hash FROM public.saas_platform_auth_sessions"
                )
        for statement in (
            "SELECT principal_id FROM public.saas_model_publication_disablements",
            "INSERT INTO public.saas_model_publication_disablements DEFAULT VALUES",
            "UPDATE public.saas_model_publication_disablements SET through_generation=2",
            "DELETE FROM public.saas_model_publication_disablements",
        ):
            with pytest.raises(sa.exc.DBAPIError, match="permission denied"):
                with f.app.begin() as connection:
                    connection.exec_driver_sql(statement)
        for verb in (
            "UPDATE public.saas_model_publication_disablements SET through_generation=2",
            "DELETE FROM public.saas_model_publication_disablements",
        ):
            with pytest.raises(sa.exc.DBAPIError, match="immutable"):
                with f.engine.begin() as connection:
                    connection.exec_driver_sql(verb)
        # A second generation can be published, but raw Staff writes cannot omit its audit intent.
        newer = source.admit(
            actor,
            **{
                **request,
                "expected_generation": 1,
                "idempotency_key": "publish-after-real-disable",
            },
        )
        publisher.publish(**_envelope(factory, newer.id))
        assert customer.list(runtime)[0]["generation"] == 2
        with pytest.raises(sa.exc.DBAPIError, match="audit intent missing"):
            with sessions.begin() as db:
                apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))
                facts = db.execute(
                    sa.text(
                        "SELECT clock_timestamp(),"
                        "(SELECT max(generation) FROM public.saas_model_publication_versions),"
                        "(SELECT count(*) FROM public.saas_platform_auth_sessions "
                        " WHERE id=:session AND principal_id=:principal AND revoked_at IS NULL)"
                    ),
                    {"session": actor.session_id, "principal": actor.principal_id},
                ).one()
                assert facts[1:] == (2, 1)
                record_property(
                    "database_clock_offset_ms",
                    round((datetime.now(timezone.utc) - facts[0]).total_seconds() * 1000, 3),
                )
                db.add(
                    ModelPublicationDisablementRecord(
                        id=uuid4(),
                        tenant_id=publication.tenant_id,
                        public_model_id=publication.public_model_id,
                        wire_api=publication.wire_api,
                        through_generation=2,
                        principal_id=actor.principal_id,
                        staff_session_id=actor.session_id,
                        staff_security_version=actor.security_version,
                        idempotency_key="raw-without-audit",
                        request_hash="a" * 64,
                        created_at=facts[0],
                    )
                )
        assert customer.list(runtime)[0]["generation"] == 2
        with pytest.raises(RuntimeError, match="retained model disablement"):
            with f.engine.begin() as connection:
                config = Config(f.role_sql.parent / "alembic.ini")
                config.attributes["connection"] = connection
                command.downgrade(config, "lm2k00000001")
        with f.engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT relforcerowsecurity FROM pg_class "
                "WHERE oid='public.saas_model_publication_disablements'::regclass"
            ).scalar_one()
    finally:
        if staff is not None:
            staff.dispose()
        if created:
            with f.engine.begin() as connection:
                connection.exec_driver_sql(f"DROP OWNED BY {role}")
                connection.exec_driver_sql(f"DROP ROLE {role}")
