"""Exercise budget settlement using the actual non-bypass schema-owner login."""

from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.platform_models import (
    ModelProviderConfigurationRecord,
    PlatformStaffPrincipalRecord,
)
from saas.production import postgresql_migration as migration
from tests.saas.test_execution_control_plane import _admitted_run, _execution_fixture
from tests.saas.test_standalone_model_schema import (
    production_replay as production_replay,
)
from tests.saas.test_standalone_model_schema import (
    standalone_replay as standalone_replay,
)

_RPC = "public.saas_apply_model_provider_budget_usage(uuid,uuid,uuid,bigint,bigint)"


def test_non_bypass_budget_owner_settlement_is_exact_and_bounded(standalone_replay):
    verify_non_bypass_budget_owner_settlement(standalone_replay)


def verify_non_bypass_budget_owner_settlement(plan):
    receipt = migration.run_production_postgresql_migration(plan)
    assert receipt.saas_head == migration._expected_head("saas")
    admin_url = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"])
    admin = sa.create_engine(
        admin_url.set(database=plan.saas_owner.url.database, query=plan.saas_owner.url.query)
    )
    owner = sa.create_engine(plan.saas_owner.url)
    app = sa.create_engine(
        plan.saas_owner.url.set(username=plan.service_role_graph.login_for("app"))
    )
    billing = sa.create_engine(
        plan.saas_owner.url.set(username=plan.service_role_graph.login_for("billing"))
    )
    try:
        _factory, _service, scope, context = _execution_fixture(admin, create_schema=False)
        execution = ExecutionControlPlane(sessionmaker(app, expire_on_commit=False))
        execution.configure_quota(
            context, project_id=scope.project_id, resource="run_units", limit_units=2
        )
        run_id, _task, _session = _admitted_run(execution, scope, context)
        with admin.begin() as db:
            now = db.exec_driver_sql("SELECT CURRENT_TIMESTAMP").scalar_one()
            principal = uuid4()
            factory = sessionmaker(bind=db, expire_on_commit=False)
            with factory.begin() as session:
                session.add(
                    PlatformStaffPrincipalRecord(
                        id=principal,
                        identity_connection_ref="owner-budget-fixture",
                        issuer="https://staff-idp.example.test",
                        subject=str(principal),
                        status="active",
                        security_version=1,
                    )
                )
                session.flush()
                session.add(
                    ModelProviderConfigurationRecord(
                        provider_id="deepseek",
                        enabled=True,
                        base_url="https://api.deepseek.com",
                        api_type="openai_chat_completions",
                        api_key_ciphertext="synthetic-not-a-key",
                        allowed_models=["synthetic"],
                        default_model="synthetic",
                        monthly_budget_microusd=10_000_000,
                        per_tenant_daily_token_limit=10_000,
                        verification_status="verified",
                        last_verified_model="synthetic",
                        last_verified_at=now,
                        version=1,
                        updated_by_principal_id=principal,
                        updated_at=now,
                    )
                )
        budgets = ModelProviderBudgetAdmissionService(
            sessionmaker(billing, expire_on_commit=False)
        )
        common = {
            "tenant_id": scope.tenant_id,
            "run_id": run_id,
            "ttl": timedelta(minutes=5),
        }
        target = budgets.reserve(
            **common,
            operation_key="owner-settlement-target",
            requested_microusd=500_000,
            requested_tokens=2000,
            now=now,
        )
        other = budgets.reserve(
            **common,
            operation_key="owner-settlement-other",
            requested_microusd=200_000,
            requested_tokens=1000,
            now=now,
        )
        expired = budgets.reserve(
            **common,
            operation_key="owner-settlement-expired",
            requested_microusd=100_000,
            requested_tokens=1000,
            now=now - timedelta(minutes=10),
        )

        def bind(db, reservation):
            db.execute(
                sa.text(
                    "SELECT set_config('app.model_budget_reservation_id',:reservation,true),"
                    "set_config('app.metering_tenant_id',:tenant,true),"
                    "set_config('app.metering_run_id',:run,true)"
                ),
                {
                    "reservation": str(reservation),
                    "tenant": str(scope.tenant_id),
                    "run": str(run_id),
                },
            )

        def settle(db, reservation, amount=250_000, tokens=1000):
            db.execute(
                sa.text(
                    "SELECT public.saas_apply_model_provider_budget_usage("
                    ":reservation,:tenant,:run,:amount,:tokens)"
                ),
                {
                    "reservation": reservation,
                    "tenant": scope.tenant_id,
                    "run": run_id,
                    "amount": amount,
                    "tokens": tokens,
                },
            )

        def totals(db):
            return db.execute(
                sa.text(
                    "SELECT id,settled_microusd,settled_tokens,version "
                    "FROM saas_model_provider_budget_reservations "
                    "WHERE id IN (:target,:other,:expired) "
                    "ORDER BY id"
                ),
                {"target": target.id, "other": other.id, "expired": expired.id},
            ).all()

        with owner.begin() as db:
            assert db.exec_driver_sql(
                "SELECT current_user=session_user,rolsuper,rolbypassrls,rolcreaterole "
                "FROM pg_roles WHERE rolname=current_user"
            ).one() == (True, False, False, False)
            assert db.execute(
                sa.text(
                    "SELECT has_function_privilege('saas_metering',:rpc,'EXECUTE'),"
                    "has_table_privilege('saas_metering','saas_model_provider_budget_reservations','UPDATE'),"
                    "has_function_privilege(:app,:rpc,'EXECUTE')"
                ),
                {"rpc": _RPC, "app": plan.service_role_graph.login_for("app")},
            ).one() == (True, False, False)
            before = totals(db)
            assert (
                db.execute(
                    sa.text(
                        "UPDATE saas_model_provider_budget_reservations SET updated_at=updated_at "
                        "WHERE id=:id RETURNING id"
                    ),
                    {"id": target.id},
                ).all()
                == []
            )
            with pytest.raises(
                sa.exc.DBAPIError, match="model budget metering context is invalid"
            ):
                with db.begin_nested():
                    settle(db, target.id)
            bind(db, target.id)
            assert (
                db.execute(
                    sa.text(
                        "UPDATE saas_model_provider_budget_reservations SET updated_at=updated_at "
                        "WHERE id=:id RETURNING id"
                    ),
                    {"id": other.id},
                ).all()
                == []
            )
            settle(db, target.id)
            settled = totals(db)
            assert len(settled) == len(before) == 3
            row = next(item for item in settled if item.id == target.id)
            assert (row.settled_microusd, row.settled_tokens) == (250_000, 1000)
            for reservation, amount, tokens in (
                (target.id, 300_000, 1000),
                (expired.id, 10_000, 1),
            ):
                with pytest.raises(
                    sa.exc.DBAPIError, match="model budget reservation is unavailable or exhausted"
                ):
                    with db.begin_nested():
                        bind(db, reservation)
                        settle(db, reservation, amount, tokens)
                assert totals(db) == settled
        verified = migration.run_production_postgresql_migration(plan, verify_only=True)
        assert verified.catalog_sha256 == receipt.catalog_sha256
    finally:
        for engine in (owner, app, billing, admin):
            engine.dispose()
