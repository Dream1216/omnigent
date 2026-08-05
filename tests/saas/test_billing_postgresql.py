from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import BillingControlPlane, BillingControlPlaneError

NOW = datetime(2026, 8, 6, 5, tzinfo=timezone.utc)


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for billing RLS acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _seed_tenants(
    connection: sa.Connection,
    *,
    owner_a: UUID,
    owner_b: UUID,
    tenant_a: UUID,
    tenant_b: UUID,
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_global_users (id, status, security_version) VALUES "
            "(:owner_a, 'active', 1), (:owner_b, 'active', 1)"
        ),
        {"owner_a": owner_a, "owner_b": owner_b},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_tenants "
            "(id, slug, name, status, plan, home_region) VALUES "
            "(:tenant_a, :slug_a, 'Billing A', 'active', 'team', 'cn-east-1'), "
            "(:tenant_b, :slug_b, 'Billing B', 'active', 'team', 'cn-east-1')"
        ),
        {
            "tenant_a": tenant_a,
            "slug_a": f"billing-a-{tenant_a.hex}",
            "tenant_b": tenant_b,
            "slug_b": f"billing-b-{tenant_b.hex}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_tenant_memberships "
            "(tenant_id, user_id, role, status, version) VALUES "
            "(:tenant_a, :owner_a, 'owner', 'active', 1), "
            "(:tenant_b, :owner_b, 'owner', 'active', 1)"
        ),
        {
            "tenant_a": tenant_a,
            "owner_a": owner_a,
            "tenant_b": tenant_b,
            "owner_b": owner_b,
        },
    )


def _bootstrap(
    control: BillingControlPlane,
    *,
    tenant_id: UUID,
    owner_id: UUID,
    suffix: str,
) -> tuple[UUID, UUID]:
    control.configure_subscription(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v1",
        status="active",
        current_period_start=NOW,
        current_period_end=NOW + timedelta(days=30),
        expected_version=None,
        idempotency_key=f"pg-subscription-{suffix}",
    )
    pricing = control.create_pricing_snapshot(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v1",
        currency="USD",
        rates={
            "llm.input_tokens": {
                "unit": "tokens",
                "unit_size": "1",
                "minor_per_unit": 25,
            }
        },
        effective_from=NOW,
        effective_until=NOW + timedelta(days=30),
        idempotency_key=f"pg-pricing-{suffix}",
    )
    entitlement = control.set_entitlement(
        actor_id=owner_id,
        tenant_id=tenant_id,
        scope_type="tenant",
        meter="llm.input_tokens",
        unit="tokens",
        limit_quantity="100",
        concurrency_limit=2,
        hard_limit=True,
        period="month",
        period_start=NOW,
        period_end=NOW + timedelta(days=30),
        status="active",
        expected_version=None,
        idempotency_key=f"pg-entitlement-{suffix}",
    )
    return pricing.id, entitlement.id


def test_real_postgresql_billing_rls_append_only_and_concurrent_reservation() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=6, max_overflow=2)
    owner_a, owner_b, tenant_a, tenant_b = uuid4(), uuid4(), uuid4(), uuid4()
    suffix = uuid4().hex[:12]
    billing_role = f"saas_billing_acceptance_{suffix}"

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"CREATE ROLE {billing_role} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT; "
            f"GRANT saas_billing TO {billing_role}; SET LOCAL ROLE saas_platform"
        )
        _seed_tenants(
            connection,
            owner_a=owner_a,
            owner_b=owner_b,
            tenant_a=tenant_a,
            tenant_b=tenant_b,
        )

    sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(sessions, "after_begin")
    def _use_billing_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {billing_role}")

    control = BillingControlPlane(sessions)
    pricing_a, entitlement_a = _bootstrap(
        control,
        tenant_id=tenant_a,
        owner_id=owner_a,
        suffix=f"a-{suffix}",
    )
    _bootstrap(
        control,
        tenant_id=tenant_b,
        owner_id=owner_b,
        suffix=f"b-{suffix}",
    )
    control.grant_credit(
        actor_id=owner_a,
        tenant_id=tenant_a,
        amount_minor=100,
        currency="USD",
        idempotency_key=f"pg-credit-{suffix}",
        occurred_at=NOW,
    )

    barrier = Barrier(2)

    def _reserve(index: int) -> str:
        barrier.wait(timeout=10)
        try:
            control.reserve(
                actor_id=owner_a,
                tenant_id=tenant_a,
                entitlement_id=entitlement_a,
                operation_key=f"pg-run-{suffix}-{index}",
                quantity="80",
                amount_minor=80,
                currency="USD",
                idempotency_key=f"pg-reserve-{suffix}-{index}",
                now=NOW + timedelta(minutes=1),
            )
        except BillingControlPlaneError as error:
            return error.code
        return "reserved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(_reserve, (1, 2)))
    assert results.count("reserved") == 1
    assert len(set(results) & {"entitlement_limit_exceeded", "billing_credit_exhausted"}) == 1

    overview = control.get_overview(actor_id=owner_a, tenant_id=tenant_a)
    assert overview["balance"] is not None
    assert overview["balance"].available_minor == 20
    assert overview["balance"].reserved_minor == 80
    assert overview["entitlements"][0].reserved_quantity == 80
    balance_version = overview["balance"].version
    assert control.audit_balance(actor_id=owner_a, tenant_id=tenant_a).consistent is True

    with pytest.raises(BillingControlPlaneError) as pricing_overlap:
        control.create_pricing_snapshot(
            actor_id=owner_a,
            tenant_id=tenant_a,
            plan_key="team-v1",
            currency="USD",
            rates={
                "llm.input_tokens": {
                    "unit": "tokens",
                    "unit_size": "1",
                    "minor_per_unit": 30,
                }
            },
            effective_from=NOW + timedelta(days=29),
            effective_until=NOW + timedelta(days=60),
            idempotency_key=f"pg-pricing-overlap-{suffix}",
        )
    assert pricing_overlap.value.code == "pricing_window_overlap"

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "UPDATE saas_billing_balances SET available_minor = 19 WHERE tenant_id = :tenant"
            ),
            {"tenant": tenant_a},
        )
    assert control.audit_balance(actor_id=owner_a, tenant_id=tenant_a).consistent is False
    rebuilt = control.rebuild_balance(
        actor_id=owner_a,
        tenant_id=tenant_a,
        expected_version=balance_version,
        reason="PostgreSQL acceptance fixture repairs an injected projection drift.",
        idempotency_key=f"pg-balance-rebuild-{suffix}",
    )
    assert rebuilt.consistent is True
    assert rebuilt.projection.available_minor == 20
    assert rebuilt.projection.reserved_minor == 80

    usage = control.record_usage(
        actor_id=owner_a,
        tenant_id=tenant_a,
        pricing_snapshot_id=pricing_a,
        meter="llm.input_tokens",
        quantity="1",
        unit="tokens",
        provider="openai",
        provider_request_id=f"pg-provider-{suffix}",
        idempotency_key=f"pg-usage-{suffix}",
        occurred_at=NOW + timedelta(minutes=2),
        attributes={"model": "gpt-5"},
    )
    batch = control.reconcile(
        actor_id=owner_a,
        tenant_id=tenant_a,
        period_start=NOW,
        period_end=NOW + timedelta(days=1),
        idempotency_key=f"pg-reconcile-{suffix}",
    )
    assert batch.status == "exception"
    mismatches = control.list_reconciliation_mismatches(
        actor_id=owner_a,
        tenant_id=tenant_a,
        batch_id=batch.id,
    )
    assert {item["mismatch_type"] for item in mismatches} == {
        "missing_customer_settlement",
        "missing_provider_cost",
    }
    mismatch_id = UUID(str(mismatches[0]["id"]))
    control.resolve_mismatch(
        actor_id=owner_a,
        tenant_id=tenant_a,
        mismatch_id=mismatch_id,
        resolution="Finance case FIN-PG owns the verified exception.",
        idempotency_key=f"pg-resolve-{suffix}",
        now=NOW + timedelta(days=1, minutes=1),
    )

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {billing_role}")
        without_context = connection.execute(
            sa.text("SELECT count(*) FROM saas_billing_subscriptions")
        ).scalar_one()
        assert without_context == 0
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :tenant, true)"),
            {"tenant": str(tenant_a)},
        )
        tenant_a_rows = connection.execute(
            sa.text("SELECT tenant_id FROM saas_billing_subscriptions")
        ).scalars()
        assert set(tenant_a_rows) == {tenant_a}
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :tenant, true)"),
            {"tenant": str(tenant_b)},
        )
        tenant_b_rows = connection.execute(
            sa.text("SELECT tenant_id FROM saas_billing_subscriptions")
        ).scalars()
        assert set(tenant_b_rows) == {tenant_b}

    with pytest.raises(sa.exc.DBAPIError, match="Billing fact is append-only"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text("UPDATE saas_usage_events SET meter = meter WHERE id = :usage"),
                {"usage": usage.id},
            )
    with pytest.raises(sa.exc.DBAPIError, match="Billing fact is append-only"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text("DELETE FROM saas_billing_reconciliation_batches WHERE id = :batch"),
                {"batch": batch.id},
            )
    with pytest.raises(sa.exc.DBAPIError, match="Billing mismatch transition is invalid"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_billing_reconciliation_mismatches "
                    "SET status = 'open' WHERE id = :mismatch"
                ),
                {"mismatch": mismatch_id},
            )

    with engine.begin() as connection:
        protected = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class "
                    "WHERE relrowsecurity AND relforcerowsecurity AND ("
                    "relname LIKE 'saas_billing_%' OR "
                    "relname IN ('saas_pricing_snapshots', 'saas_usage_events', "
                    "'saas_customer_ledger_entries', 'saas_provider_cost_entries'))"
                )
            ).scalars()
        )
        assert protected == {
            "saas_billing_subscriptions",
            "saas_pricing_snapshots",
            "saas_billing_entitlements",
            "saas_usage_events",
            "saas_billing_balances",
            "saas_billing_reservations",
            "saas_customer_ledger_entries",
            "saas_provider_cost_entries",
            "saas_billing_reconciliation_batches",
            "saas_billing_reconciliation_mismatches",
        }
        posture = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname IN ('saas_billing', :child) ORDER BY rolname"
            ),
            {"child": billing_role},
        ).all()
        assert len(posture) == 2
        assert all(not superuser and not bypass for _role, superuser, bypass in posture)
        privileges = connection.execute(
            sa.text(
                "SELECT "
                "has_table_privilege('saas_billing', 'saas_usage_events', 'SELECT'), "
                "has_table_privilege('saas_billing', 'saas_usage_events', 'UPDATE'), "
                "has_table_privilege('saas_app', 'saas_usage_events', 'SELECT'), "
                "has_table_privilege('saas_governance', 'saas_usage_events', 'SELECT'), "
                "has_table_privilege(:child, 'saas_projects', 'SELECT')"
            ),
            {"child": billing_role},
        ).one()
        assert privileges == (True, False, False, False, False)
        connection.exec_driver_sql(f"REVOKE saas_billing FROM {billing_role}")
        connection.exec_driver_sql(f"DROP ROLE {billing_role}")
    engine.dispose()
