from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_gateway_audit import (
    GATEWAY_AUDIT_SIGNATURE,
    ModelGatewayAuditPublisher,
    verify_gateway_audit_function,
)
from saas.control_plane.outbox import OutboxDispatcher, OutboxPublishError
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_governed_access import PlatformGovernedAccessService
from saas.control_plane.platform_governed_models import PlatformAuditEventRecord
from saas.control_plane.platform_models import (
    ModelProviderConfigurationRecord,
    PlatformRoleAssignmentRecord,
)
from saas.control_plane.retained_model_audit import RetainedModelAuditPublisher
from saas.outbox_worker import verify_dispatcher_database_role
from tests.saas.test_model_connections import _fixture as _staff_fixture
from tests.saas.test_platform_model_gateway import TENANT_ID
from tests.saas.test_platform_model_gateway_attempts import _body, _fixture


def _assign_control_plane_owner(connection, current_owner, target):
    quoted = connection.dialect.identifier_preparer.quote
    parameters = {"owner": current_owner}
    relations = connection.execute(
        sa.text(
            "SELECT relname,relkind FROM pg_class WHERE relnamespace='public'::regnamespace "
            "AND left(relname,5)='saas_' AND relkind IN ('r','p','S','v','m','f') "
            "AND relowner=(SELECT oid FROM pg_roles WHERE rolname=:owner) ORDER BY relname"
        ),
        parameters,
    ).all()
    for name, kind in relations:
        object_type = "SEQUENCE" if kind == "S" else "TABLE"
        connection.exec_driver_sql(
            f"ALTER {object_type} public.{quoted(name)} OWNER TO {quoted(target)}"
        )
    functions = connection.execute(
        sa.text(
            "SELECT proname,pg_get_function_identity_arguments(oid) FROM pg_proc "
            "WHERE pronamespace='public'::regnamespace AND (left(proname,5)='saas_' "
            "OR proname IN ('approval_source_work_binding_is_valid',"
            "'approval_notification_binding_is_valid')) "
            "AND proowner=(SELECT oid FROM pg_roles WHERE rolname=:owner)"
        ),
        parameters,
    ).all()
    for name, arguments in functions:
        connection.exec_driver_sql(
            f"ALTER FUNCTION public.{quoted(name)}({arguments}) OWNER TO {quoted(target)}"
        )


class _RejectFallback:
    def publish(self, **_event):
        raise AssertionError("gateway audit must not fall through")


@pytest.fixture
def audit_gateway(tmp_path, isolated_postgres_url):
    root = Path(__file__).resolve().parents[2]
    owner = sa.create_engine(isolated_postgres_url)
    quoted = owner.dialect.identifier_preparer.quote
    suffix = uuid4().hex
    audit_owner, dispatch_login, billing_login = (
        "audit_" + name + suffix for name in ("o", "d", "b")
    )
    password = "isolated-gateway-audit-test-only"
    database = sa.make_url(isolated_postgres_url).database
    dispatcher = billing = None
    roles = []
    try:
        with owner.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            for name in (audit_owner, dispatch_login, billing_login):
                login = "NOLOGIN" if name == audit_owner else f"LOGIN PASSWORD '{password}'"
                connection.exec_driver_sql(
                    f"CREATE ROLE {quoted(name)} {login} NOSUPERUSER NOBYPASSRLS "
                    "NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT"
                )
                roles.append(name)
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher TO {quoted(dispatch_login)} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f"GRANT saas_billing TO {quoted(billing_login)} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted(database)} "
                f"TO saas_dispatcher,{quoted(billing_login)}"
            )
        _, sessions, actor, _, _, _ = _staff_fixture(engine=owner)
        now = datetime.now(timezone.utc)
        with sessions.begin() as db:
            db.add(
                ModelProviderConfigurationRecord(
                    provider_id="deepseek",
                    enabled=True,
                    base_url="https://api.deepseek.com",
                    api_type="openai_chat_completions",
                    api_key_ciphertext="isolated-not-a-key",
                    allowed_models=["deepseek-flash"],
                    default_model="deepseek-flash",
                    monthly_budget_microusd=100_000_000,
                    per_tenant_daily_token_limit=100_000_000,
                    verification_status="verified",
                    last_verified_model="deepseek-flash",
                    last_verified_at=now,
                    version=7,
                    updated_by_principal_id=actor.principal_id,
                    updated_at=now,
                )
            )
            db.add(
                PlatformRoleAssignmentRecord(
                    id=uuid4(),
                    principal_id=actor.principal_id,
                    role="platform_security_auditor",
                    status="active",
                    version=1,
                    assigned_by_principal_id=actor.principal_id,
                    approval_ref="isolated-audit-fixture",
                    reason="isolated audit acceptance",
                    created_at=now,
                    updated_at=now,
                )
            )
        actor = replace(
            actor,
            roles=actor.roles | {"platform_security_auditor"},
            permissions=actor.permissions | PLATFORM_ROLE_PERMISSIONS["platform_security_auditor"],
        )
        billing = sa.create_engine(
            sa.make_url(isolated_postgres_url).set(username=billing_login, password=password)
        )
        dispatcher = sa.create_engine(
            sa.make_url(isolated_postgres_url).set(username=dispatch_login, password=password)
        )
        budgets = ModelProviderBudgetAdmissionService(
            sessionmaker(billing, expire_on_commit=False)
        )
        calls = []

        def upstream(request):
            calls.append(request)
            return httpx.Response(
                200, content=_body(), headers={"content-type": "text/event-stream"}
            )

        client, path, request, _, _, _ = _fixture(
            tmp_path, upstream, budget_database=(budgets, sessions)
        )
        with owner.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT USAGE,CREATE ON SCHEMA public TO {quoted(audit_owner)}"
            )
            _assign_control_plane_owner(connection, "postgres", audit_owner)
            connection.exec_driver_sql(
                f"REVOKE CREATE ON SCHEMA public FROM {quoted(audit_owner)}"
            )
        publisher = ModelGatewayAuditPublisher(dispatcher, _RejectFallback())
        yield SimpleNamespace(
            owner=owner,
            sessions=sessions,
            actor=actor,
            billing=billing,
            dispatcher=dispatcher,
            publisher=publisher,
            client=client,
            path=path,
            request=request,
            config=config,
            calls=calls,
            audit_owner=audit_owner,
        )
    finally:
        for engine in (billing, dispatcher):
            if engine is not None:
                engine.dispose()
        with owner.begin() as connection:
            if audit_owner in roles:
                _assign_control_plane_owner(connection, audit_owner, "postgres")
            for name in reversed(roles):
                connection.exec_driver_sql(f"DROP OWNED BY {quoted(name)}")
                connection.exec_driver_sql(f"DROP ROLE {quoted(name)}")
        owner.dispose()


def _event(row):
    return {
        "event_id": row.id,
        "event_type": row.event_type,
        "aggregate_type": row.aggregate_type,
        "aggregate_key": row.aggregate_key,
        "payload": row.payload,
    }


def _state(fixture):
    with fixture.owner.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT settled_microusd,reserved_microusd FROM saas_model_provider_monthly_budgets"
        ).one(), connection.exec_driver_sql(
            "SELECT count(*) FROM saas_customer_ledger_entries"
        ).scalar_one()


@pytest.mark.parametrize("retained", (False, True), ids=("specialized", "retained"))
def test_real_postgresql_gateway_audit_survives_lost_ack_and_preserves_shared_chain(
    audit_gateway, retained
):
    f = audit_gateway
    if retained:
        f.publisher = RetainedModelAuditPublisher(f.dispatcher, _RejectFallback())
    verify_dispatcher_database_role(f.dispatcher)
    f.publisher.validate_outbox_configuration()
    assert f.client.post(f.path, **f.request).status_code == 200
    before = _state(f)
    service = PlatformGovernedAccessService(f.sessions)
    with f.sessions.begin() as db:
        service._append_audit(
            db,
            tenant_id=TENANT_ID,
            actor_type="staff",
            actor_id=f.actor.principal_id,
            event_type="platform.fixture.started",
            target_type="tenant",
            target_id=TENANT_ID,
            operation_id=None,
            payload={"fixture": True},
            occurred_at=datetime.now(timezone.utc).replace(microsecond=0),
        )

    class AckLost(OutboxDispatcher):
        def _acknowledge(self, *_args, **_kwargs):
            raise OSError("isolated acknowledgement loss")

    now = datetime.now(timezone.utc)
    dispatcher_sessions = sessionmaker(f.dispatcher, expire_on_commit=False)
    with pytest.raises(OSError, match="acknowledgement"):
        AckLost(dispatcher_sessions, f.publisher).dispatch_once(now=now)
    with f.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditEventRecord)) == 2
        assert all(
            row.published_at is None for row in db.scalars(sa.select(ControlPlaneOutboxEvent))
        )
    result = OutboxDispatcher(dispatcher_sessions, f.publisher).dispatch_once(
        now=now + timedelta(minutes=2)
    )
    assert (result.claimed, result.published, result.failed) == (3, 3, 0)
    with f.sessions() as db:
        events = db.scalars(sa.select(ControlPlaneOutboxEvent)).all()
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditEventRecord)) == 4
    for event in events:
        f.publisher.publish(**_event(event))
    assert service.verify_audit_chain(f.actor)
    assert _state(f) == before == ((13, 0), 0)
    assert len(f.calls) == 1
    for sql in (
        "SELECT * FROM saas_model_gateway_evidence",
        "SELECT * FROM saas_platform_audit_events",
        "SELECT api_key_ciphertext FROM saas_model_provider_configurations",
        "UPDATE saas_platform_audit_chain_heads SET last_sequence=0",
        "SET ROLE saas_platform_governance",
    ):
        with pytest.raises(DBAPIError) as denied, f.dispatcher.begin() as connection:
            connection.exec_driver_sql(sql)
        assert denied.value.orig.sqlstate == "42501"
    with pytest.raises(DBAPIError) as denied, f.billing.begin() as connection:
        connection.exec_driver_sql("SELECT public.saas_audit_model_gateway_evidence_v1(NULL,NULL)")
    assert denied.value.orig.sqlstate == "42501"


def test_real_postgresql_gateway_audit_deduplicates_concurrent_out_of_order_delivery(
    audit_gateway,
):
    f = audit_gateway
    assert f.client.post(f.path, **f.request).status_code == 200
    with f.sessions() as db:
        events = db.scalars(
            sa.select(ControlPlaneOutboxEvent).order_by(ControlPlaneOutboxEvent.created_at)
        ).all()
    reordered = [events[2], events[0], events[1]]
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda row: f.publisher.publish(**_event(row)), reordered * 3))
    with f.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditEventRecord)) == 3
    assert PlatformGovernedAccessService(f.sessions).verify_audit_chain(f.actor)
    assert _state(f) == ((13, 0), 0)
    first = _event(events[0])
    for mutation in (
        {"tenant_id": str(uuid4())},
        {"evidence_id": str(uuid4())},
        {"evidence_sha256": "0" * 64},
    ):
        with pytest.raises(OutboxPublishError) as rejected:
            f.publisher.publish(**{**first, "payload": {**first["payload"], **mutation}})
        assert rejected.value.code == "model_gateway_audit_evidence_rejected"
        assert not rejected.value.retryable and rejected.value.pre_side_effect
    with (
        pytest.raises(RuntimeError, match="retained gateway audit"),
        f.owner.begin() as connection,
    ):
        f.config.attributes["connection"] = connection
        command.downgrade(f.config, "lm2b00000001")
    with f.dispatcher.connect() as connection:
        assert verify_gateway_audit_function(connection) is not None


def test_real_postgresql_gateway_audit_transaction_failure_is_retried_without_partial_append(
    audit_gateway,
):
    f = audit_gateway
    assert f.client.post(f.path, **f.request).status_code == 200
    with f.owner.begin() as connection:
        connection.exec_driver_sql("""
            CREATE FUNCTION public.isolated_audit_failure() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated audit storage failure'
                USING ERRCODE='08006'; END $$;
            CREATE TRIGGER isolated_audit_failure BEFORE UPDATE
            ON public.saas_platform_audit_chain_heads FOR EACH ROW
            EXECUTE FUNCTION public.isolated_audit_failure();
        """)
    dispatcher = OutboxDispatcher(sessionmaker(f.dispatcher, expire_on_commit=False), f.publisher)
    now = datetime.now(timezone.utc)
    result = dispatcher.dispatch_once(now=now)
    assert (result.claimed, result.published, result.failed) == (3, 0, 3)
    with f.owner.connect() as connection:
        assert (
            connection.exec_driver_sql(
                "SELECT count(*) FROM saas_platform_audit_events"
            ).scalar_one()
            == 0
        )
        assert (
            connection.exec_driver_sql(
                "SELECT last_sequence FROM saas_platform_audit_chain_heads"
            ).scalar_one()
            == 0
        )
    with f.owner.begin() as connection:
        connection.exec_driver_sql("""
            DROP TRIGGER isolated_audit_failure ON public.saas_platform_audit_chain_heads;
            DROP FUNCTION public.isolated_audit_failure();
        """)
    retried = dispatcher.dispatch_once(now=now + timedelta(minutes=2))
    assert (retried.claimed, retried.published, retried.failed) == (3, 3, 0)
    assert PlatformGovernedAccessService(f.sessions).verify_audit_chain(f.actor)
    assert _state(f) == ((13, 0), 0)
    assert len(f.calls) == 1


def test_real_postgresql_gateway_audit_recovers_a_committed_rpc_reply_loss(audit_gateway):
    f = audit_gateway
    assert f.client.post(f.path, **f.request).status_code == 200
    with f.sessions() as db:
        event = db.scalar(sa.select(ControlPlaneOutboxEvent))

    class ReplyLost(Exception):
        sqlstate = "08006"

    class CommitReplyLost:
        @contextmanager
        def begin(self):
            with f.dispatcher.begin() as connection:
                yield connection
            raise OperationalError("isolated lost commit reply", {}, ReplyLost())

    f.publisher._engine = CommitReplyLost()
    try:
        with pytest.raises(OutboxPublishError) as uncertain:
            f.publisher.publish(**_event(event))
        assert uncertain.value.retryable and not uncertain.value.pre_side_effect
    finally:
        f.publisher._engine = f.dispatcher
    with f.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditEventRecord)) == 1
        assert db.get(ControlPlaneOutboxEvent, event.id).published_at is None
    result = OutboxDispatcher(
        sessionmaker(f.dispatcher, expire_on_commit=False), f.publisher
    ).dispatch_once()
    assert (result.claimed, result.published, result.failed) == (3, 3, 0)
    with f.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditEventRecord)) == 3
    assert PlatformGovernedAccessService(f.sessions).verify_audit_chain(f.actor)
    assert _state(f) == ((13, 0), 0) and len(f.calls) == 1


def test_real_postgresql_gateway_audit_source_and_acl_drift_are_rejected(audit_gateway):
    f = audit_gateway
    with f.owner.connect() as connection:
        definition = connection.scalar(
            sa.text("SELECT pg_get_functiondef(to_regprocedure(:signature))"),
            {"signature": GATEWAY_AUDIT_SIGNATURE},
        )
    for recipient in ("PUBLIC", "saas_billing"):
        with f.owner.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT EXECUTE ON FUNCTION {GATEWAY_AUDIT_SIGNATURE} TO {recipient}"
            )
        with pytest.raises(RuntimeError, match="function_contract_rejected"):
            verify_dispatcher_database_role(f.dispatcher)
        with f.owner.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE EXECUTE ON FUNCTION {GATEWAY_AUDIT_SIGNATURE} FROM {recipient}"
            )
        verify_dispatcher_database_role(f.dispatcher)
    with f.owner.begin() as connection:
        connection.execute(sa.text(definition.replace("RETURN true;", "RETURN false;")))
    with pytest.raises(RuntimeError, match="function_contract_rejected"):
        verify_dispatcher_database_role(f.dispatcher)
    with f.owner.begin() as connection:
        connection.execute(sa.text(definition))
    for change, restore in (
        ("STRICT", "CALLED ON NULL INPUT"),
        ("SET search_path=public", "SET search_path=pg_catalog, pg_temp"),
    ):
        with f.owner.begin() as connection:
            connection.exec_driver_sql(f"ALTER FUNCTION {GATEWAY_AUDIT_SIGNATURE} {change}")
        with pytest.raises(RuntimeError, match="function_contract_rejected"):
            verify_dispatcher_database_role(f.dispatcher)
        with f.owner.begin() as connection:
            connection.exec_driver_sql(f"ALTER FUNCTION {GATEWAY_AUDIT_SIGNATURE} {restore}")
        verify_dispatcher_database_role(f.dispatcher)
    with f.owner.begin() as connection:
        connection.exec_driver_sql("""
            CREATE FUNCTION public.isolated_unrelated_rpc() RETURNS integer LANGUAGE sql
            SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 1';
            REVOKE ALL ON FUNCTION public.isolated_unrelated_rpc() FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION public.isolated_unrelated_rpc() TO saas_dispatcher;
        """)
    with pytest.raises(RuntimeError, match="unsafe direct or delegable authority"):
        verify_dispatcher_database_role(f.dispatcher)
    with f.owner.begin() as connection:
        connection.exec_driver_sql("DROP FUNCTION public.isolated_unrelated_rpc()")
    verify_dispatcher_database_role(f.dispatcher)
    with f.owner.begin() as connection:
        f.config.attributes["connection"] = connection
        command.downgrade(f.config, "lm2b00000001")
    verify_dispatcher_database_role(f.dispatcher)
    with pytest.raises(RuntimeError, match="function_unavailable"):
        f.publisher.validate_outbox_configuration()
    with f.owner.begin() as connection:
        quoted = connection.dialect.identifier_preparer.quote(f.audit_owner)
        connection.exec_driver_sql(f"GRANT CREATE ON SCHEMA public TO {quoted}")
        connection.exec_driver_sql(f"SET LOCAL ROLE {quoted}")
        f.config.attributes["connection"] = connection
        command.upgrade(f.config, "head")
        connection.exec_driver_sql("RESET ROLE")
        connection.exec_driver_sql(f"REVOKE CREATE ON SCHEMA public FROM {quoted}")
    verify_dispatcher_database_role(f.dispatcher)
    f.publisher.validate_outbox_configuration()
