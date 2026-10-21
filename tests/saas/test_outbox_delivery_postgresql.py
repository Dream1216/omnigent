"""Real PostgreSQL security/commit boundaries; no production or KMS claim."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker

from saas.control_plane.billing import BillingControlPlane
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    Tenant,
    TenantMembership,
)
from saas.control_plane.outbox import OutboxDispatcher, OutboxPublishError
from saas.control_plane.outbox_delivery import (
    PlatformAuditJournalConsumer,
    UsageReconciliationConsumer,
)
from saas.control_plane.outbox_delivery_models import (
    PlatformAuditJournalDeliveryRecord,
    RevocationReplicaAppliedRecord,
    UsageReconciliationIngressRecord,
)
from saas.control_plane.platform_governed_access import PlatformGovernedAccessService
from saas.control_plane.revocation import (
    AuthorizationInvalidations,
    NativeRevocationFollower,
    ReplicaRevocationConsumer,
    RevocationFanoutPublisher,
)
from tests.saas.test_audit_journal_delivery import _Cipher, _Signer
from tests.saas.test_billing_control_plane import NOW, _bootstrap
from tests.saas.test_slo_observability import _Store


@pytest.fixture
def delivery_database(isolated_postgres_url):
    """Reuse the native disposable DB; actual DDL owner has no bypass/role powers."""
    url = sa.make_url(isolated_postgres_url)
    engine = sa.create_engine(url)
    root = Path(__file__).resolve().parents[2]
    owner = "delivery_owner_" + uuid4().hex[:16]
    profiles = {
        "usage": "saas_usage_consumer",
        "audit": "saas_audit_delivery",
        "revocation": "saas_revocation_consumer",
        "app": "saas_app",
        "billing": "saas_billing",
        "dispatcher": "saas_dispatcher",
    }
    logins = {name: "delivery_" + name + "_" + uuid4().hex[:12] for name in profiles}
    passwords = {name: secrets.token_urlsafe(32) for name in profiles}
    other_engines = {}
    try:
        with engine.begin() as db:
            db.exec_driver_sql(
                f'CREATE ROLE "{owner}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                "NOBYPASSRLS NOINHERIT"
            )
            db.exec_driver_sql(f'GRANT USAGE,CREATE ON SCHEMA public TO "{owner}"')
            db.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            config = Config(root / "saas/control_plane/alembic.ini")
            config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
            config.attributes["connection"] = db
            command.upgrade(config, "head")
        # Exercise the real production revoke-and-reconstruct path, not just
        # Alembic's initial grants. A separate owner connection has no bypass.
        from saas.production.postgresql_migration import _apply_control_plane_authority

        owner_engine = sa.create_engine(url)

        @sa.event.listens_for(owner_engine, "connect")
        def direct_owner(connection, _record):
            connection.execute('SET ROLE "' + owner + '"')

        try:
            _apply_control_plane_authority(owner_engine)
        finally:
            owner_engine.dispose()
        with engine.begin() as db:
            for name, role in profiles.items():
                login = logins[name]
                db.exec_driver_sql(
                    f'CREATE ROLE "{login}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                    "NOBYPASSRLS INHERIT"
                )
                # Bind the fresh disposable secret through transaction-local GUCs.
                # No password enters SQL text, argv, environment or public receipts.
                raw = db.connection.driver_connection
                try:
                    raw.execute(
                        "SELECT set_config('app.test_login',%s,true),"
                        "set_config('app.test_password',%s,true)",
                        (login, passwords[name]),
                    )
                    raw.execute(
                        "DO $test$ BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L',"
                        "current_setting('app.test_login'),"
                        "current_setting('app.test_password')); END $test$"
                    )
                    raw.execute(
                        "SELECT set_config('app.test_password','',true),"
                        "set_config('app.test_login','',true)"
                    )
                except Exception:
                    raise RuntimeError("disposable native login setup failed") from None
                db.exec_driver_sql(f'GRANT "{role}" TO "{login}"')
                db.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{url.database}" TO "{login}"')
            flags = db.execute(
                sa.text(
                    "SELECT rolsuper,rolbypassrls,rolcreaterole FROM pg_roles WHERE rolname=:owner"
                ),
                {"owner": owner},
            ).one()
            assert tuple(flags) == (False, False, False)
            assert (
                db.exec_driver_sql("SELECT version_num FROM saas_alembic_version").scalar_one()
                == "p0s000000017"
            )
        factories = {}
        for name, login in logins.items():
            query = dict(url.query)
            if name == "revocation":
                query["application_name"] = "saas-revocation-worker"
            other_engines[name] = sa.create_engine(
                url.set(username=login, password=passwords[name], query=query)
            )
            factories[name] = sessionmaker(other_engines[name], expire_on_commit=False)
        admin = sessionmaker(engine, expire_on_commit=False)
        user, tenant = uuid4(), uuid4()
        with admin.begin() as db:
            db.add_all(
                [
                    GlobalUser(id=user, status="active", security_version=1),
                    Tenant(
                        id=tenant,
                        slug="delivery-" + tenant.hex,
                        name="Delivery",
                        status="active",
                        plan="team",
                        home_region="cn-east-1",
                    ),
                ]
            )
            db.flush()
            db.add(
                TenantMembership(
                    tenant_id=tenant, user_id=user, role="owner", status="active", version=1
                )
            )
        yield admin, factories, other_engines, user, tenant
    finally:
        for item in other_engines.values():
            item.dispose()
        engine.dispose()
        # Exact fixture database and roles only; underlying helper's IF EXISTS
        # cleanup is idempotent after this owner-principal dependency cleanup.
        supervisor = sa.create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
        try:
            with supervisor.connect() as db:
                db.exec_driver_sql(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')
                for role in (*logins.values(), owner):
                    db.exec_driver_sql(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            supervisor.dispose()


def _outbox(row):
    return {
        "event_id": row.id,
        "event_type": row.event_type,
        "aggregate_type": row.aggregate_type,
        "aggregate_key": row.aggregate_key,
        "payload": row.payload,
    }


def test_actual_usage_getters_receiver_commit_and_least_role_denials(delivery_database):
    admin, factories, engines, user, tenant = delivery_database
    billing = BillingControlPlane(admin)
    pricing, _ = _bootstrap(billing, tenant, user)
    usage = billing.record_usage(
        actor_id=user,
        tenant_id=tenant,
        pricing_snapshot_id=pricing,
        meter="llm.input_tokens",
        quantity="1000",
        unit="tokens",
        provider="openai",
        provider_request_id="actual-native-ingress",
        idempotency_key="actual-native-usage",
        occurred_at=NOW + timedelta(minutes=1),
    )
    consumer = UsageReconciliationConsumer(factories["usage"], product_revision="a" * 40)
    dispatcher = OutboxDispatcher(admin, consumer, claim_routes=consumer.claim_routes)
    result = dispatcher.dispatch_once()
    assert (result.claimed, result.published, result.failed) == (1, 1, 0)
    with admin() as db:
        source = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(usage.id)
            )
        )
        event = _outbox(source)
        receipt = db.get(UsageReconciliationIngressRecord, source.id)
        assert receipt.usage_event_id == usage.id
    consumer.publish(**event)
    # The actual billing login can see only its tenant's received facts, and
    # reports real missing finance; the delivery worker cannot create finance.
    strict = BillingControlPlane(factories["billing"], require_usage_ingress=True)
    report = strict.reconcile(
        actor_id=user,
        tenant_id=tenant,
        period_start=NOW,
        period_end=NOW + timedelta(days=1),
        idempotency_key="actual-native-reconcile",
    )
    assert report.status == "exception" and report.provider_cost_count == 0
    for name, statement in [
        ("usage", "SELECT token_hash FROM saas_api_credentials"),
        ("usage", "SELECT * FROM saas_customer_ledger_entries"),
        ("usage", "SELECT * FROM saas_delivery_audit_outbox_source_v1(NULL)"),
        ("app", "SELECT * FROM saas_delivery_usage_outbox_source_v1(NULL)"),
        ("app", "SELECT * FROM saas_usage_reconciliation_ingress"),
    ]:
        with engines[name].connect() as db, pytest.raises(sa.exc.DBAPIError):
            db.exec_driver_sql(statement)
            db.rollback()
    with factories["usage"].begin() as db, pytest.raises(sa.exc.DBAPIError):
        db.execute(sa.delete(UsageReconciliationIngressRecord))
    with admin.begin() as db:
        other = Tenant(
            slug="other-" + uuid4().hex,
            name="Other",
            status="active",
            plan="team",
            home_region="cn-east-1",
        )
        db.add(other)
        db.flush()
        forged = ControlPlaneOutboxEvent(
            tenant_id=other.id,
            aggregate_type=event["aggregate_type"],
            aggregate_key=event["aggregate_key"],
            event_type=event["event_type"],
            payload=event["payload"],
            request_hash="f" * 64,
            idempotency_key="cross-tenant-" + uuid4().hex,
        )
        db.add(forged)
        db.flush()
        forged_event = _outbox(forged)
    with pytest.raises(OutboxPublishError) as denied:
        consumer.publish(**forged_event)
    assert denied.value.code == "usage_scope_mismatch"


def test_actual_audit_trigger_nonbypass_getter_chain_and_immutable_receipt(delivery_database):
    admin, factories, engines, user, tenant = delivery_database
    service = PlatformGovernedAccessService(admin)
    with admin.begin() as db:
        audit = service._append_audit(
            db,
            tenant_id=tenant,
            actor_type="customer",
            actor_id=user,
            event_type="native.delivery.acceptance",
            target_type="tenant",
            target_id=tenant,
            operation_id=None,
            payload={"synthetic": "native-audit-only"},
            occurred_at=datetime.now(UTC),
        )
        db.flush()
        source = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_type == "platform_audit"
            )
        )
        assert source.aggregate_key == str(audit.id)
        event = _outbox(source)
    consumer = PlatformAuditJournalConsumer(
        factories["audit"], _Store(), _Cipher(), _Signer(), product_revision="a" * 40
    )
    consumer.publish(**event)
    consumer.publish(**event)
    with admin() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditJournalDeliveryRecord))
            == 1
        )
    for name, query in [
        ("audit", "SELECT * FROM saas_platform_audit_exports"),
        ("audit", "SELECT * FROM saas_delivery_usage_outbox_source_v1(NULL)"),
        ("app", "SELECT public.saas_delivery_audit_backfill_v1(0,128)"),
    ]:
        with engines[name].connect() as db, pytest.raises(sa.exc.DBAPIError):
            db.exec_driver_sql(query)
    with admin.begin() as db, pytest.raises(sa.exc.DBAPIError):
        db.execute(sa.update(PlatformAuditJournalDeliveryRecord).values(storage_version="forged"))
    with admin.begin() as db, pytest.raises(sa.exc.DBAPIError):
        db.execute(
            sa.update(ControlPlaneOutboxEvent)
            .where(ControlPlaneOutboxEvent.id == event["event_id"])
            .values(payload={"forged": True})
        )


def test_actual_commit_only_notify_two_boots_and_disconnect_recovery(delivery_database):
    admin, factories, engines, user, _ = delivery_database
    monotonic = [100.0]
    caches = [AuthorizationInvalidations(clock=lambda: monotonic[0]) for _ in range(2)]
    consumers = [
        ReplicaRevocationConsumer(
            factories["revocation"], cache, product_revision="a" * 40, replica_uid=uuid4()
        )
        for cache in caches
    ]

    def connect():
        args, kwargs = engines["revocation"].dialect.create_connect_args(engines["revocation"].url)
        import psycopg

        return psycopg.connect(*args, **kwargs, autocommit=True)

    followers = [NativeRevocationFollower(consumer, connect) for consumer in consumers]
    try:
        assert not any(follower.step() for follower in followers)
        monotonic[0] += 65.0
        assert all(follower.step() for follower in followers)
        transaction = admin()
        try:
            transaction.begin()
            transaction.get(GlobalUser, user).security_version = 2
            transaction.flush()
            for follower in followers:
                follower.step()
            assert all(cache.minimum("user", user) == 0 for cache in caches)
            transaction.commit()
        finally:
            transaction.close()
        assert followers[0].step()
        with admin() as db:
            source = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_type == "authorization_user"
                )
            )
            envelope = _outbox(source)
        publisher = RevocationFanoutPublisher(factories["revocation"], product_revision="a" * 40)
        with pytest.raises(OutboxPublishError) as pending:
            publisher.publish(**envelope)
        assert pending.value.code == "fanout_receivers_pending"
        assert followers[1].step()
        # Native role can observe the exact public connection identity fields;
        # no pg_read_all_stats/BYPASS grant is used for fanout completeness.
        with factories["revocation"]() as db:
            names = db.scalars(
                sa.text(
                    "SELECT application_name FROM pg_stat_activity "
                    "WHERE datname=current_database() AND usename=session_user "
                    "AND backend_type='client backend'"
                )
            ).all()
            assert len([n for n in names if n.startswith("saas-revocation-listen:")]) == 2
            assert all(
                n == "saas-revocation-worker" or n.startswith("saas-revocation-listen:")
                for n in names
            ), names
            acknowledged = set(
                db.scalars(sa.select(RevocationReplicaAppliedRecord.listener_epoch_uid))
            )
            assert {c.listener_epoch_uid for c in consumers} <= acknowledged
        publisher.publish(**envelope)
        assert all(cache.minimum("user", user) == 2 for cache in caches)
        with admin() as db:
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(RevocationReplicaAppliedRecord))
                == 2
            )
            row = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_type == "authorization_user"
                )
            )
            assert (
                row.published_at is None
            )  # One/two ACKs alone do not self-authorize a global terminal.
        with engines["revocation"].connect() as unknown:
            unknown.exec_driver_sql("SET LOCAL application_name='unexpected-purpose'")
            with pytest.raises(OutboxPublishError) as rejected:
                publisher.publish(**envelope)
            assert rejected.value.code == "fanout_receivers_pending"
        dispatcher = OutboxDispatcher(
            factories["dispatcher"], publisher, claim_routes=publisher.claim_routes
        )
        result = dispatcher.dispatch_once()
        assert (result.claimed, result.published, result.failed) == (1, 1, 0)
        with admin() as db:
            assert db.get(ControlPlaneOutboxEvent, envelope["event_id"]).published_at is not None
        old_listener_epoch = consumers[0].listener_epoch_uid
        followers[0]._connection.close()
        from psycopg import OperationalError

        with pytest.raises(OperationalError):
            followers[0].step()
        assert not caches[0].ready
        assert not followers[0].step() and caches[0].minimum("user", user) == 2
        monotonic[0] += 65.0
        assert followers[0].step()
        assert consumers[0].listener_epoch_uid != old_listener_epoch
        publisher.publish(**envelope)
        replacement = ReplicaRevocationConsumer(
            factories["revocation"],
            AuthorizationInvalidations(clock=lambda: monotonic[0]),
            product_revision="a" * 40,
            replica_uid=consumers[0].replica_uid,
        )
        pending_connection = connect()
        pending_connection.execute(
            "SELECT set_config('application_name',%s,false)",
            ("saas-revocation-listen:" + uuid4().hex,),
        )
        pending_connection.execute(f"LISTEN {NativeRevocationFollower.channel}")
        with pytest.raises(OutboxPublishError) as late_join:
            publisher.publish(**envelope)
        assert late_join.value.code == "fanout_receivers_pending"
        assert not replacement.cache.ready
        fresh = NativeRevocationFollower(replacement, lambda: pending_connection)
        followers.append(fresh)
        assert not fresh.step() and replacement.cache.minimum("user", user) == 2
        monotonic[0] += 65.0
        assert fresh.step()
        publisher.publish(**envelope)
        assert replacement.process_boot_uid != consumers[0].process_boot_uid
        with admin() as db:
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(RevocationReplicaAppliedRecord))
                == 4
            )
    finally:
        for follower in followers:
            follower.close()


def test_late_native_commit_behind_real_scan_cursor_is_applied_before_ready(delivery_database):
    admin, factories, engines, _, _ = delivery_database
    identities = [uuid4(), uuid4()]
    with admin.begin() as db:
        db.add_all(
            [GlobalUser(id=entity, status="active", security_version=1) for entity in identities]
        )
    held = [admin(), admin()]
    followers = []
    try:
        sources = []
        for transaction, entity in zip(held, identities, strict=True):
            transaction.begin()
            transaction.get(GlobalUser, entity).security_version = 2
            transaction.flush()
            sources.append(
                transaction.scalar(
                    sa.select(ControlPlaneOutboxEvent).where(
                        ControlPlaneOutboxEvent.aggregate_key == str(entity)
                    )
                )
            )
        late, early = sorted(range(2), key=lambda index: sources[index].id)
        held[early].commit()

        def connect():
            import psycopg

            args, kwargs = engines["revocation"].dialect.create_connect_args(
                engines["revocation"].url
            )
            return psycopg.connect(*args, **kwargs, autocommit=True)

        monotonic = [100.0]
        consumers = [
            ReplicaRevocationConsumer(
                factories["revocation"],
                AuthorizationInvalidations(clock=lambda: monotonic[0]),
                product_revision="a" * 40,
                replica_uid=uuid4(),
            )
            for _ in range(2)
        ]
        followers = [NativeRevocationFollower(consumer, connect) for consumer in consumers]
        assert not any(follower.step() for follower in followers)
        monotonic[0] += 65.0
        assert all(follower.step() for follower in followers)
        for follower in followers:
            assert follower._cursor > sources[late].id  # Real SQL scan, no cursor injection.
            assert follower.consumer.cache.minimum("user", identities[late]) == 0
        held[late].commit()
        assert all(follower.step() for follower in followers)
        assert all(consumer.cache.minimum("user", identities[late]) == 2 for consumer in consumers)
        publisher = RevocationFanoutPublisher(factories["revocation"], product_revision="a" * 40)
        publisher.publish(**_outbox(sources[late]))
        with admin() as db:
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(RevocationReplicaAppliedRecord))
                == 4
            )
    finally:
        for follower in followers:
            follower.close()
        for transaction in held:
            transaction.close()


def test_native_revocation_history_live_and_reconnect_have_distinct_real_metrics(
    delivery_database,
):
    from saas.observability import SloMetrics
    from tests.saas.test_slo_observability import _metric_sample

    admin, factories, engines, user, _ = delivery_database
    with admin.begin() as db:
        db.get(GlobalUser, user).security_version = 2
    monotonic = [100.0]
    cache = AuthorizationInvalidations(clock=lambda: monotonic[0])
    metrics = SloMetrics()
    consumer = ReplicaRevocationConsumer(
        factories["revocation"],
        cache,
        product_revision="a" * 40,
        replica_uid=uuid4(),
        metrics=metrics,
    )

    def connect():
        import psycopg

        args, kwargs = engines["revocation"].dialect.create_connect_args(engines["revocation"].url)
        return psycopg.connect(*args, **kwargs, autocommit=True)

    follower = NativeRevocationFollower(consumer, connect)
    success = (
        'saas_slo_stage_duration_seconds_count{stage="revocation_invalidation",outcome="success"}'
    )
    replay = (
        'saas_slo_stage_duration_seconds_count{stage="revocation_invalidation",outcome="replayed"}'
    )
    degraded = 'saas_slo_operations_total{operation="revocation_degraded",outcome="replayed"}'
    try:
        assert not follower.step() and cache.minimum("user", user) == 2
        actual = metrics.render().decode()
        assert _metric_sample(actual, success) == 0 and _metric_sample(actual, replay) == 1
        assert _metric_sample(actual, degraded) == 1
        monotonic[0] = 165.0
        assert follower.step()
        with admin.begin() as db:
            db.get(GlobalUser, user).security_version = 3
        assert follower.step() and cache.minimum("user", user) == 3
        actual = metrics.render().decode()
        assert _metric_sample(actual, success) == 1 and _metric_sample(actual, replay) == 1
        follower._connection.close()
        from psycopg import OperationalError

        with pytest.raises(OperationalError):
            follower.step()
        assert not cache.ready
        with admin.begin() as db:
            db.get(GlobalUser, user).security_version = 4
        assert not follower.step() and cache.minimum("user", user) == 4
        actual = metrics.render().decode()
        assert _metric_sample(actual, success) == 1
        assert _metric_sample(actual, replay) == 4 and _metric_sample(actual, degraded) == 4
        monotonic[0] = 230.0
        assert follower.step()
        with admin() as db:
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(RevocationReplicaAppliedRecord))
                == 5
            )
    finally:
        follower.close()
