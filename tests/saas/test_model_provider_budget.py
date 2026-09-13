from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
    ModelProviderMonthlyBudgetRecord,
    ModelProviderTenantDailyUsageRecord,
)

NOW = datetime(2026, 9, 14, 4, 0, tzinfo=timezone.utc)


def _service(tmp_path: Path) -> tuple[ModelProviderBudgetAdmissionService, sessionmaker[Session]]:
    engine = sa.create_engine(f"sqlite+pysqlite:///{tmp_path / 'budget.sqlite'}")
    for table in (
        ModelProviderConfigurationRecord.__table__,
        ModelProviderMonthlyBudgetRecord.__table__,
        ModelProviderTenantDailyUsageRecord.__table__,
        ModelProviderBudgetReservationRecord.__table__,
    ):
        table.create(engine)
    sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
    with sessions.begin() as db:
        db.add(
            ModelProviderConfigurationRecord(
                provider_id="deepseek",
                enabled=True,
                base_url="https://api.deepseek.com",
                api_type="openai_chat_completions",
                api_key_ciphertext="encrypted-provider-key",
                allowed_models=["deepseek-v4-flash"],
                default_model="deepseek-v4-flash",
                monthly_budget_microusd=1_000,
                per_tenant_daily_token_limit=1_000,
                verification_status="verified",
                last_verified_model="deepseek-v4-flash",
                last_verified_at=NOW,
                version=3,
                updated_by_principal_id=uuid4(),
                updated_at=NOW,
            )
        )
    return ModelProviderBudgetAdmissionService(sessions), sessions


def test_budget_reserve_reject_settle_and_idempotent_replay(tmp_path: Path) -> None:
    service, sessions = _service(tmp_path)
    tenant_id, run_id = uuid4(), uuid4()
    reserved = service.reserve(
        tenant_id=tenant_id,
        run_id=run_id,
        operation_key="run:first",
        requested_microusd=600,
        requested_tokens=700,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    assert reserved.status == "reserved"
    assert reserved.configuration_version == 3
    replay = service.reserve(
        tenant_id=tenant_id,
        run_id=run_id,
        operation_key="run:first",
        requested_microusd=600,
        requested_tokens=700,
        ttl=timedelta(minutes=5),
        now=NOW + timedelta(seconds=1),
    )
    assert replay.id == reserved.id and replay.replayed

    monthly_rejected = service.reserve(
        tenant_id=uuid4(),
        run_id=uuid4(),
        operation_key="run:monthly-reject",
        requested_microusd=500,
        requested_tokens=1,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    assert monthly_rejected.status == "rejected"
    assert monthly_rejected.rejection_code == "platform_model_monthly_budget_exhausted"
    daily_rejected = service.reserve(
        tenant_id=tenant_id,
        run_id=uuid4(),
        operation_key="run:daily-reject",
        requested_microusd=1,
        requested_tokens=301,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    assert daily_rejected.rejection_code == "platform_model_tenant_daily_tokens_exhausted"

    settled = service.settle(
        reservation_id=reserved.id,
        actual_microusd=450,
        actual_tokens=650,
        now=NOW + timedelta(minutes=1),
    )
    assert settled.status == "settled"
    assert (settled.released_microusd, settled.released_tokens) == (150, 50)
    replayed_settlement = service.settle(
        reservation_id=reserved.id,
        actual_microusd=450,
        actual_tokens=650,
        now=NOW + timedelta(minutes=2),
    )
    assert replayed_settlement.replayed
    with sessions.begin() as db:
        monthly = db.get(ModelProviderMonthlyBudgetRecord, ("deepseek", NOW.date().replace(day=1)))
        daily = db.get(ModelProviderTenantDailyUsageRecord, (tenant_id, "deepseek", NOW.date()))
        assert monthly is not None
        assert (monthly.reserved_microusd, monthly.settled_microusd) == (0, 450)
        assert daily is not None
        assert (daily.reserved_tokens, daily.settled_tokens) == (0, 650)


def test_budget_release_and_expiry_recovery_return_reserved_capacity(tmp_path: Path) -> None:
    service, sessions = _service(tmp_path)
    first = service.reserve(
        tenant_id=uuid4(),
        run_id=uuid4(),
        operation_key="run:release",
        requested_microusd=400,
        requested_tokens=400,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    released = service.release(reservation_id=first.id, now=NOW + timedelta(minutes=1))
    assert released.status == "released"
    assert service.release(reservation_id=first.id, now=NOW + timedelta(minutes=2)).replayed

    expired = service.reserve(
        tenant_id=uuid4(),
        run_id=uuid4(),
        operation_key="run:expire",
        requested_microusd=500,
        requested_tokens=500,
        ttl=timedelta(seconds=1),
        now=NOW,
    )
    recovered = service.recover_expired(now=NOW + timedelta(seconds=2))
    assert [item.id for item in recovered] == [expired.id]
    assert recovered[0].status == "expired"
    with sessions.begin() as db:
        monthly = db.get(ModelProviderMonthlyBudgetRecord, ("deepseek", NOW.date().replace(day=1)))
        assert monthly is not None
        assert (monthly.reserved_microusd, monthly.settled_microusd) == (0, 0)


def test_metered_deltas_settle_atomically_before_unused_reservation_is_released(
    tmp_path: Path,
) -> None:
    service, sessions = _service(tmp_path)
    tenant_id, run_id = uuid4(), uuid4()
    reservation = service.reserve(
        tenant_id=tenant_id,
        run_id=run_id,
        operation_key="run:metered",
        requested_microusd=900,
        requested_tokens=900,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    with sessions.begin() as db:
        applied = service.apply_metered_usage(
            db,
            reservation_id=reservation.id,
            tenant_id=tenant_id,
            run_id=run_id,
            actual_microusd=250,
            actual_tokens=300,
            now=NOW + timedelta(seconds=1),
        )
        assert (applied.settled_microusd, applied.settled_tokens) == (250, 300)
    finalized = service.release(
        reservation_id=reservation.id,
        now=NOW + timedelta(seconds=2),
    )
    assert finalized.status == "released"
    assert (finalized.released_microusd, finalized.released_tokens) == (650, 600)
    with sessions.begin() as db:
        monthly = db.get(ModelProviderMonthlyBudgetRecord, ("deepseek", NOW.date().replace(day=1)))
        daily = db.get(ModelProviderTenantDailyUsageRecord, (tenant_id, "deepseek", NOW.date()))
        assert monthly is not None and daily is not None
        assert (monthly.reserved_microusd, monthly.settled_microusd) == (0, 250)
        assert (daily.reserved_tokens, daily.settled_tokens) == (0, 300)
