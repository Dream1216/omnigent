from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_revocation_audit import ModelRevocationAuditPublisher
from saas.control_plane.model_revocations import REVOCATION_EVENT
from saas.control_plane.model_routing_models import ModelPublicationRevocationRecord
from saas.control_plane.outbox import OutboxClaimRoute, OutboxDispatcher, OutboxPublishError
from saas.control_plane.platform_governed_models import PlatformAuditEventRecord
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_password_auth import PlatformPasswordAuthenticationService
from saas.control_plane.platform_security import PlatformSecurityError, PlatformSessionService
from saas.control_plane.retained_model_audit import RetainedModelAuditPublisher
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context
from saas.outbox_worker import verify_dispatcher_database_role
from tests.saas.postgresql_retention import assert_retained_downgrade_refused
from tests.saas.test_model_disablement_audit_postgresql import (
    audit_disablement as audit_disablement,
)
from tests.saas.test_model_gateway_audit_postgresql import _event, _RejectFallback
from tests.saas.test_model_gateway_audit_postgresql import audit_gateway as audit_gateway


def _request(f):
    service = f.disable_service.security_revocations
    args = {
        "disablement_id": f.disablement["disablement_id"],
        "expected_generation": 1,
        "idempotency_key": "audit-revocation-001",
    }
    receipt = service.request(f.actor, **args)
    assert service.request(f.actor, **args) == receipt
    with f.sessions() as db:
        event = db.scalars(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.event_type == REVOCATION_EVENT
            )
        ).one()
    return receipt, _event(event)


@pytest.mark.parametrize("retained", (False, True), ids=("specialized", "retained"))
def test_real_staff_revocation_and_dispatcher_lost_ack_retain_one_shared_audit_fact(
    audit_disablement,
    retained,
):
    f = audit_disablement
    receipt, event = _request(f)
    publisher = (
        RetainedModelAuditPublisher(f.dispatcher, _RejectFallback())
        if retained
        else ModelRevocationAuditPublisher(f.dispatcher, f.publisher)
    )
    publisher.validate_outbox_configuration()
    verify_dispatcher_database_role(f.dispatcher)
    route = OutboxClaimRoute("platform_model", REVOCATION_EVENT, REVOCATION_EVENT)

    class AckLost(OutboxDispatcher):
        def _acknowledge(self, *_args, **_kwargs):
            raise OSError("isolated revocation acknowledgement loss")

    now = datetime.now(timezone.utc)
    with pytest.raises(OSError, match="acknowledgement loss"):
        AckLost(f.dispatcher_sessions, publisher, claim_routes=(route,)).dispatch_once(now=now)
    with f.sessions() as db:
        row = db.get(PlatformAuditEventRecord, event["event_id"])
        assert row.actor_type == "staff" and row.actor_id == f.actor.principal_id
        assert row.target_id == receipt["revocation_id"]
        assert row.target_type == "model_publication_revocation"
        assert row.tenant_id == f.publication_request["tenant_id"]
        assert db.get(ControlPlaneOutboxEvent, event["event_id"]).published_at is None
        assert row.payload["through_generation"] == 1
    repeated = OutboxDispatcher(
        f.dispatcher_sessions, publisher, claim_routes=(route,)
    ).dispatch_once(now=now + timedelta(minutes=2))
    assert (repeated.claimed, repeated.published, repeated.failed) == (1, 1, 0)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: publisher.publish(**event), range(8)))
    f.publisher.publish(**f.disablement_event)
    assert f.audit_service.verify_audit_chain(f.actor)
    with f.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditEventRecord)) == 3
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationRevocationRecord))
            == 1
        )
    for statement in (
        "SELECT * FROM public.saas_model_publication_revocations",
        "SELECT * FROM public.saas_runs",
        "UPDATE public.saas_runs SET status='cancelled'",
        "SELECT token_hash FROM public.saas_platform_auth_sessions",
        "SET ROLE saas_platform_app",
    ):
        with pytest.raises(DBAPIError) as error, f.dispatcher.begin() as db:
            db.exec_driver_sql(statement)
        assert error.value.orig.sqlstate == "42501"
    for statement in (
        "UPDATE public.saas_model_publication_revocations SET through_generation=2",
        "DELETE FROM public.saas_model_publication_revocations",
    ):
        with pytest.raises(DBAPIError, match="immutable"), f.owner.begin() as db:
            db.exec_driver_sql(statement)
    assert_retained_downgrade_refused(
        f.owner, "lm2m00000001", expected_pattern="retained model security revocation"
    )
    with f.owner.connect() as db:
        assert db.exec_driver_sql(
            "SELECT relforcerowsecurity FROM pg_class "
            "WHERE oid='public.saas_model_publication_revocations'::regclass"
        ).scalar_one()


def test_real_revocation_audit_rejects_forged_reference_and_rolls_back_storage_failure(
    audit_disablement,
):
    f = audit_disablement
    receipt, event = _request(f)
    publisher = ModelRevocationAuditPublisher(f.dispatcher, f.publisher)
    wrong = {**event, "payload": {**event["payload"], "schema_version": True}}
    with pytest.raises(OutboxPublishError) as rejected:
        publisher.publish(**wrong)
    assert not rejected.value.retryable and rejected.value.pre_side_effect
    with f.owner.begin() as db:
        db.exec_driver_sql(
            "CREATE FUNCTION public.isolated_revoke_audit_failure() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated storage failure'; END $$"
        )
        db.exec_driver_sql(
            "CREATE TRIGGER isolated_revoke_audit_failure BEFORE INSERT "
            "ON public.saas_platform_audit_events FOR EACH ROW "
            "EXECUTE FUNCTION public.isolated_revoke_audit_failure()"
        )
    try:
        with pytest.raises(OutboxPublishError) as unavailable:
            publisher.publish(**event)
        assert unavailable.value.retryable
        with f.sessions() as db:
            assert db.get(PlatformAuditEventRecord, event["event_id"]) is None
            assert db.get(ModelPublicationRevocationRecord, receipt["revocation_id"]) is not None
    finally:
        with f.owner.begin() as db:
            db.exec_driver_sql(
                "DROP TRIGGER isolated_revoke_audit_failure ON public.saas_platform_audit_events"
            )
            db.exec_driver_sql("DROP FUNCTION public.isolated_revoke_audit_failure()")
    publisher.publish(**event)
    assert f.audit_service.verify_audit_chain(f.actor)


def _second_operator(f):
    now = datetime.now(timezone.utc)
    sessions = PlatformSessionService(
        f.sessions, origin="https://staff.example.test", audience="model-management"
    )
    passwords = PlatformPasswordAuthenticationService(f.sessions, sessions)
    identifier = passwords.provision_account(
        username="second-revoker", password="isolated-second-revoker-password", now=now
    )
    with f.sessions.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                id=uuid4(),
                principal_id=identifier,
                assigned_by_principal_id=f.actor.principal_id,
                role="platform_operator",
                status="active",
                version=1,
                approval_ref="isolated-test",
                reason="isolated concurrency",
                created_at=now,
                updated_at=now,
            )
        )
    issued = passwords.authenticate("second-revoker", "isolated-second-revoker-password", now=now)
    return sessions.validate_session(
        issued.token, origin="https://staff.example.test", audience="model-management"
    )


def test_real_fresh_staff_cannot_forge_scope_or_omit_audit_and_concurrent_staff_share_one_cutoff(
    audit_disablement,
):
    f = audit_disablement
    cutoff, actor = f.disablement, f.actor
    for change, message in (("audit", "audit intent missing"), ("scope", "authority changed")):
        with pytest.raises(DBAPIError, match=message):
            with f.disable_service._session("test_rejected_raw_security_intent") as db:
                apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))
                at = db.scalar(sa.select(sa.func.clock_timestamp()))
                db.add(
                    ModelPublicationRevocationRecord(
                        id=uuid4(),
                        disablement_id=cutoff["disablement_id"],
                        tenant_id=uuid4() if change == "scope" else cutoff["tenant_id"],
                        public_model_id=cutoff["public_model_id"],
                        wire_api=cutoff["wire_api"],
                        through_generation=cutoff["through_generation"],
                        principal_id=actor.principal_id,
                        staff_session_id=actor.session_id,
                        staff_security_version=actor.security_version,
                        idempotency_key="raw-security-" + change,
                        request_hash="b" * 64,
                        created_at=at,
                    )
                )
    other = _second_operator(f)

    def request(principal):
        try:
            return f.disable_service.security_revocations.request(
                principal,
                disablement_id=cutoff["disablement_id"],
                expected_generation=1,
                idempotency_key="concurrent-security-001",
            )
        except PlatformSecurityError as error:
            assert error.code == "platform_model_revocation_conflict"
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(request, (actor, other)))
    assert sum(result is not None for result in results) == 1
    with f.sessions() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationRevocationRecord))
            == 1
        )
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == REVOCATION_EVENT)
            )
            == 1
        )
    winner, loser = (actor, other) if results[0] is not None else (other, actor)
    assert (
        f.disable_service.security_revocations.find(
            loser, idempotency_key="concurrent-security-001"
        )
        is None
    )
    assert (
        f.disable_service.security_revocations.find(
            winner, idempotency_key="concurrent-security-001"
        )
        is not None
    )
