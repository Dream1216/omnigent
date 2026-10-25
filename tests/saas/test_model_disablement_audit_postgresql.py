from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_connections import ModelConnectionService
from saas.control_plane.model_disablement import DISABLEMENT_EVENT
from saas.control_plane.model_disablement_audit import (
    DISABLEMENT_AUDIT_SIGNATURE,
    ModelDisablementAuditPublisher,
    verify_disablement_audit_function,
)
from saas.control_plane.model_publications import ModelPublicationService
from saas.control_plane.outbox import OutboxClaimRoute, OutboxDispatcher, OutboxPublishError
from saas.control_plane.platform_governed_access import PlatformGovernedAccessService
from saas.control_plane.platform_governed_models import PlatformAuditEventRecord
from saas.control_plane.platform_security import PlatformAuthorizationService
from saas.control_plane.retained_model_audit import RetainedModelAuditPublisher
from saas.outbox_worker import verify_dispatcher_database_role
from tests.saas import test_model_projection
from tests.saas.postgresql_retention import assert_retained_downgrade_refused
from tests.saas.test_model_connections import _Cipher
from tests.saas.test_model_gateway_audit_postgresql import (
    _event,
    _RejectFallback,
    _state,
)
from tests.saas.test_model_gateway_audit_postgresql import (
    audit_gateway as audit_gateway,
)
from tests.saas.test_model_publications import _envelope, _fixture

_ROUTE = OutboxClaimRoute("platform_model", DISABLEMENT_EVENT, DISABLEMENT_EVENT)


@pytest.fixture
def audit_disablement(audit_gateway, monkeypatch):
    f = audit_gateway
    cipher = _Cipher()
    connection = ModelConnectionService(
        f.sessions, authorization=PlatformAuthorizationService(f.sessions), secret_cipher=cipher
    )
    monkeypatch.setattr(
        test_model_projection,
        "_fixture",
        lambda: (connection, f.sessions, f.actor, cipher, None, None),
    )
    source, worker, factory, actor, request, calls = _fixture()
    operation = source.admit(actor, **request)
    worker.publish(**_envelope(factory, operation.id))
    publication = source.list(actor)[0]
    role = "disable_audit_staff_" + uuid4().hex
    staff = None
    try:
        with f.owner.begin() as db:
            db.exec_driver_sql(
                f"CREATE ROLE {role} LOGIN PASSWORD 'isolated-audit-only' NOSUPERUSER "
                "NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
            )
            db.exec_driver_sql(f"GRANT saas_platform_app TO {role} WITH INHERIT TRUE, SET FALSE")
            db.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{f.owner.url.database}" TO {role}')
        staff = sa.create_engine(f.owner.url.set(username=role, password="isolated-audit-only"))
        service = ModelPublicationService(
            staff,
            authorization=PlatformAuthorizationService(sessionmaker(staff)),
            pricing=source._pricing,
        )
        receipt = service.disable(
            actor,
            publication_id=publication.id,
            expected_generation=1,
            idempotency_key="audit-disable-first",
        )
        with f.sessions() as db:
            event = db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == DISABLEMENT_EVENT
                )
            ).one()
        f.source, f.publication_worker, f.publication_factory = source, worker, factory
        f.publication_request, f.model_calls = request, calls
        f.disablement, f.disablement_event, f.disable_service = receipt, _event(event), service
        f.publisher = ModelDisablementAuditPublisher(f.dispatcher, f.publisher)
        f.dispatcher_sessions = sessionmaker(f.dispatcher, expire_on_commit=False)
        f.audit_service = PlatformGovernedAccessService(f.sessions)
        with f.sessions.begin() as db:
            f.audit_service._append_audit(
                db,
                tenant_id=request["tenant_id"],
                actor_type="staff",
                actor_id=actor.principal_id,
                event_type="platform.fixture.started",
                target_type="tenant",
                target_id=request["tenant_id"],
                operation_id=None,
                payload={"fixture": True},
                occurred_at=datetime.now(timezone.utc).replace(microsecond=0),
            )
        yield f
    finally:
        if staff is not None:
            staff.dispose()
        with f.owner.begin() as db:
            db.exec_driver_sql(f"DROP OWNED BY {role}")
            db.exec_driver_sql(f"DROP ROLE {role}")


def _dispatch(f, *, now=None, publisher=None, dispatcher_type=OutboxDispatcher):
    return dispatcher_type(
        f.dispatcher_sessions, publisher or f.publisher, claim_routes=(_ROUTE,)
    ).dispatch_once(now=now)


def _audit_count(f):
    with f.owner.connect() as db:
        return db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditEventRecord))


@pytest.mark.parametrize("retained", (False, True), ids=("specialized", "retained"))
def test_real_disablement_audit_lost_ack_uses_existing_chain_and_exact_dispatcher(
    audit_disablement,
    retained,
):
    f = audit_disablement
    if retained:
        f.publisher = RetainedModelAuditPublisher(f.dispatcher, _RejectFallback())
    verify_dispatcher_database_role(f.dispatcher)
    f.publisher.validate_outbox_configuration()
    before, calls = _state(f), list(f.model_calls)

    class AckLost(OutboxDispatcher):
        def _acknowledge(self, *_args, **_kwargs):
            raise OSError("isolated ack loss")

    now = datetime.now(timezone.utc)
    with pytest.raises(OSError, match="ack loss"):
        _dispatch(f, now=now, dispatcher_type=AckLost)
    assert _audit_count(f) == 2
    with f.sessions() as db:
        assert (
            db.get(ControlPlaneOutboxEvent, f.disablement_event["event_id"]).published_at is None
        )
        audit = db.get(PlatformAuditEventRecord, f.disablement_event["event_id"])
        assert audit.actor_type == "staff" and audit.actor_id == f.actor.principal_id
        assert audit.tenant_id == f.publication_request["tenant_id"]
        assert audit.target_id == f.disablement["disablement_id"]
        assert audit.payload["through_generation"] == 1
        assert "staff_session_id" not in audit.payload and "request_hash" not in audit.payload
    result = _dispatch(f, now=now + timedelta(minutes=2))
    assert (result.claimed, result.published, result.failed) == (1, 1, 0)
    assert _audit_count(f) == 2
    assert f.audit_service.verify_audit_chain(f.actor)
    assert _state(f) == before and f.model_calls == calls
    for sql in (
        "SELECT * FROM public.saas_model_publication_disablements",
        "SELECT * FROM public.saas_platform_audit_events",
        "UPDATE public.saas_platform_audit_chain_heads SET last_sequence=0",
        "SELECT token_hash FROM public.saas_platform_auth_sessions",
        "SET ROLE saas_platform_app",
    ):
        with pytest.raises(DBAPIError) as denied, f.dispatcher.begin() as db:
            db.exec_driver_sql(sql)
        assert denied.value.orig.sqlstate == "42501"
    with pytest.raises(DBAPIError) as denied, f.billing.begin() as db:
        db.exec_driver_sql(f"SELECT {DISABLEMENT_AUDIT_SIGNATURE.split('(')[0]}(NULL,NULL)")
    assert denied.value.orig.sqlstate == "42501"


def test_real_disablement_audit_concurrent_reordering_never_duplicates(audit_disablement):
    f = audit_disablement
    newer = f.source.admit(
        f.actor,
        **{
            **f.publication_request,
            "expected_generation": 1,
            "idempotency_key": "audit-publish-two",
        },
    )
    f.publication_worker.publish(**_envelope(f.publication_factory, newer.id))
    row = f.source.list(f.actor)[0]
    f.disable_service.disable(
        f.actor, publication_id=row.id, expected_generation=2, idempotency_key="audit-disable-two"
    )
    with f.sessions() as db:
        events = db.scalars(
            sa.select(ControlPlaneOutboxEvent)
            .where(ControlPlaneOutboxEvent.event_type == DISABLEMENT_EVENT)
            .order_by(ControlPlaneOutboxEvent.created_at.desc())
        ).all()
    assert len(events) == 2
    before = _state(f)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda event: f.publisher.publish(**_event(event)), events * 4))
    assert _audit_count(f) == 3
    assert f.audit_service.verify_audit_chain(f.actor) and _state(f) == before
    assert_retained_downgrade_refused(
        f.owner,
        "lm2l00000001",
        expected_pattern=r"^cannot remove retained model disablement audit authority$",
        guard_revision="lm2m00000001",
    )


def test_real_disablement_audit_storage_failure_rolls_back_before_outbox_ack(audit_disablement):
    f = audit_disablement
    with f.owner.begin() as db:
        db.exec_driver_sql("""
            CREATE FUNCTION public.isolated_disable_audit_failure() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated failure'; END $$;
            CREATE TRIGGER isolated_disable_audit_failure BEFORE UPDATE
            ON public.saas_platform_audit_chain_heads FOR EACH ROW
            EXECUTE FUNCTION public.isolated_disable_audit_failure();
        """)
    now = datetime.now(timezone.utc)
    result = _dispatch(f, now=now)
    assert (result.claimed, result.published, result.failed) == (1, 0, 1)
    assert _audit_count(f) == 1
    with f.owner.begin() as db:
        assert (
            db.exec_driver_sql(
                "SELECT last_sequence FROM public.saas_platform_audit_chain_heads"
            ).scalar_one()
            == 1
        )
        db.exec_driver_sql("""
            DROP TRIGGER isolated_disable_audit_failure ON public.saas_platform_audit_chain_heads;
            DROP FUNCTION public.isolated_disable_audit_failure();
        """)
    result = _dispatch(f, now=now + timedelta(minutes=2))
    assert (result.published, result.failed) == (1, 0)
    assert _audit_count(f) == 2 and f.audit_service.verify_audit_chain(f.actor)


def test_real_disablement_audit_committed_rpc_reply_loss_is_recovered(audit_disablement):
    f = audit_disablement

    @contextmanager
    def lost_reply():
        with f.dispatcher.begin() as db:
            yield db
        raise OperationalError("isolated reply loss", {}, RuntimeError("do not expose"))

    class LostReply:
        begin = staticmethod(lost_reply)

    publisher = ModelDisablementAuditPublisher(LostReply(), f.publisher)
    now = datetime.now(timezone.utc)
    result = _dispatch(f, now=now, publisher=publisher)
    assert (result.published, result.failed) == (0, 1) and _audit_count(f) == 2
    result = _dispatch(f, now=now + timedelta(minutes=2))
    assert (result.published, result.failed) == (1, 0) and _audit_count(f) == 2
    assert f.audit_service.verify_audit_chain(f.actor)


def test_real_disablement_audit_rejects_forged_reference_and_pending_downgrade(audit_disablement):
    f = audit_disablement
    identity = str(uuid4())
    forged = {
        **f.disablement_event,
        "aggregate_key": identity,
        "payload": {**f.disablement_event["payload"], "disablement_id": identity},
    }
    with pytest.raises(OutboxPublishError) as rejected:
        f.publisher.publish(**forged)
    assert rejected.value.code == "model_disablement_audit_evidence_rejected"
    assert not rejected.value.retryable and rejected.value.pre_side_effect
    assert _audit_count(f) == 1
    assert_retained_downgrade_refused(
        f.owner,
        "lm2l00000001",
        expected_pattern=r"^cannot remove retained model disablement audit authority$",
        guard_revision="lm2m00000001",
    )
    result = _dispatch(f)
    assert (result.published, result.failed) == (1, 0)


def test_real_disablement_audit_function_source_and_acl_drift_are_rejected(audit_disablement):
    f = audit_disablement
    with f.owner.connect() as db:
        definition = db.scalar(
            sa.text("SELECT pg_get_functiondef(to_regprocedure(:signature))"),
            {"signature": DISABLEMENT_AUDIT_SIGNATURE},
        )
    for recipient in ("PUBLIC", "saas_billing"):
        with f.owner.begin() as db:
            db.exec_driver_sql(
                f"GRANT EXECUTE ON FUNCTION {DISABLEMENT_AUDIT_SIGNATURE} TO {recipient}"
            )
        with pytest.raises(RuntimeError, match="function_contract_rejected"):
            verify_dispatcher_database_role(f.dispatcher)
        with f.owner.begin() as db:
            db.exec_driver_sql(
                f"REVOKE EXECUTE ON FUNCTION {DISABLEMENT_AUDIT_SIGNATURE} FROM {recipient}"
            )
        verify_dispatcher_database_role(f.dispatcher)
    with f.owner.begin() as db:
        db.execute(sa.text(definition.replace("RETURN true;", "RETURN false;")))
    with pytest.raises(RuntimeError, match="function_contract_rejected"):
        verify_dispatcher_database_role(f.dispatcher)
    with f.owner.begin() as db:
        db.execute(sa.text(definition))
    with f.dispatcher.connect() as db:
        assert verify_disablement_audit_function(db) is not None
