"""Concurrent admission and settlement for Platform-managed model usage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
    ModelProviderMonthlyBudgetRecord,
    ModelProviderTenantDailyUsageRecord,
)

_PROVIDER_ID = "deepseek"
_MAX_RESERVATION_TTL = timedelta(hours=24)


class ModelProviderBudgetError(RuntimeError):
    """Stable admission failure that carries no Provider credential data."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ModelProviderBudgetReservationView:
    id: UUID
    provider_id: str
    tenant_id: UUID
    run_id: UUID
    configuration_version: int
    requested_microusd: int
    requested_tokens: int
    admitted_microusd: int
    admitted_tokens: int
    settled_microusd: int
    settled_tokens: int
    released_microusd: int
    released_tokens: int
    status: str
    rejection_code: str | None
    expires_at: datetime
    version: int
    replayed: bool = False


class ModelProviderBudgetAdmissionService:
    """Serialize global monthly spend and per-Tenant daily token authority."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def reserve(
        self,
        *,
        tenant_id: UUID,
        run_id: UUID,
        operation_key: str,
        requested_microusd: int,
        requested_tokens: int,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView:
        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(tenant_id, "tenant")
        _positive_uuid(run_id, "run")
        _operation_key(operation_key)
        _positive_amount(requested_microusd, "microusd")
        _positive_amount(requested_tokens, "tokens")
        if ttl <= timedelta(0) or ttl > _MAX_RESERVATION_TTL:
            raise ModelProviderBudgetError(
                "platform_model_budget_request_invalid",
                "model budget reservation TTL is invalid",
            )
        period_start = date(at.year, at.month, 1)
        usage_date = at.date()
        request_hash = _request_hash(
            tenant_id=tenant_id,
            run_id=run_id,
            operation_key=operation_key,
            requested_microusd=requested_microusd,
            requested_tokens=requested_tokens,
        )
        with self._sessions.begin() as db:
            # Serialize every Provider admission without granting Billing
            # access to the encrypted API-key column. PostgreSQL uses a
            # transaction-scoped advisory lock; SQLite tests serialize on the
            # single connection/file lock.
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.select(
                        sa.func.pg_advisory_xact_lock(
                            sa.func.hashtextextended("platform-model-budget:deepseek", 0)
                        )
                    )
                )
            configuration = db.execute(
                sa.select(
                    ModelProviderConfigurationRecord.enabled,
                    ModelProviderConfigurationRecord.monthly_budget_microusd,
                    ModelProviderConfigurationRecord.per_tenant_daily_token_limit,
                    ModelProviderConfigurationRecord.verification_status,
                    ModelProviderConfigurationRecord.version,
                ).where(ModelProviderConfigurationRecord.provider_id == _PROVIDER_ID)
            ).one_or_none()
            replay = db.execute(
                sa.select(ModelProviderBudgetReservationRecord)
                .where(
                    ModelProviderBudgetReservationRecord.provider_id == _PROVIDER_ID,
                    ModelProviderBudgetReservationRecord.operation_key == operation_key,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if replay is not None:
                if replay.request_hash != request_hash:
                    raise ModelProviderBudgetError(
                        "platform_model_budget_idempotency_conflict",
                        "model budget operation key was reused with another request",
                    )
                return _view(replay, replayed=True)
            if (
                configuration is None
                or not configuration.enabled
                or configuration.verification_status != "verified"
            ):
                raise ModelProviderBudgetError(
                    "platform_model_provider_unavailable",
                    "Platform model Provider is unavailable",
                )
            self._ensure_counters(
                db,
                tenant_id=tenant_id,
                period_start=period_start,
                usage_date=usage_date,
                now=at,
            )
            monthly = db.execute(
                sa.select(ModelProviderMonthlyBudgetRecord)
                .where(
                    ModelProviderMonthlyBudgetRecord.provider_id == _PROVIDER_ID,
                    ModelProviderMonthlyBudgetRecord.period_start == period_start,
                )
                .with_for_update()
            ).scalar_one()
            daily = db.execute(
                sa.select(ModelProviderTenantDailyUsageRecord)
                .where(
                    ModelProviderTenantDailyUsageRecord.tenant_id == tenant_id,
                    ModelProviderTenantDailyUsageRecord.provider_id == _PROVIDER_ID,
                    ModelProviderTenantDailyUsageRecord.usage_date == usage_date,
                )
                .with_for_update()
            ).scalar_one()
            rejection_code: str | None = None
            if (
                monthly.reserved_microusd + monthly.settled_microusd + requested_microusd
                > configuration.monthly_budget_microusd
            ):
                rejection_code = "platform_model_monthly_budget_exhausted"
            elif (
                daily.reserved_tokens + daily.settled_tokens + requested_tokens
                > configuration.per_tenant_daily_token_limit
            ):
                rejection_code = "platform_model_tenant_daily_tokens_exhausted"
            admitted = rejection_code is None
            record = ModelProviderBudgetReservationRecord(
                id=uuid4(),
                provider_id=_PROVIDER_ID,
                tenant_id=tenant_id,
                run_id=run_id,
                operation_key=operation_key,
                request_hash=request_hash,
                configuration_version=configuration.version,
                period_start=period_start,
                usage_date=usage_date,
                requested_microusd=requested_microusd,
                requested_tokens=requested_tokens,
                admitted_microusd=requested_microusd if admitted else 0,
                admitted_tokens=requested_tokens if admitted else 0,
                settled_microusd=0,
                settled_tokens=0,
                released_microusd=0,
                released_tokens=0,
                status="reserved" if admitted else "rejected",
                rejection_code=rejection_code,
                expires_at=at + ttl,
                created_at=at,
                updated_at=at,
                version=1,
            )
            if admitted:
                monthly.reserved_microusd += requested_microusd
                monthly.version += 1
                monthly.updated_at = at
                daily.reserved_tokens += requested_tokens
                daily.version += 1
                daily.updated_at = at
            db.add(record)
            db.flush()
            return _view(record)

    def settle(
        self,
        *,
        reservation_id: UUID,
        actual_microusd: int,
        actual_tokens: int,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView:
        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(reservation_id, "reservation")
        _positive_amount(actual_microusd, "microusd")
        _positive_amount(actual_tokens, "tokens")
        with self._sessions.begin() as db:
            record = self._locked_reservation(db, reservation_id)
            if record.status == "settled":
                if (
                    record.settled_microusd != actual_microusd
                    or record.settled_tokens != actual_tokens
                ):
                    raise ModelProviderBudgetError(
                        "platform_model_budget_settlement_conflict",
                        "model budget settlement conflicts with the durable result",
                    )
                return _view(record, replayed=True)
            if record.status != "reserved" or at >= _stored_time(record.expires_at):
                raise ModelProviderBudgetError(
                    "platform_model_budget_reservation_inactive",
                    "model budget reservation is not active",
                )
            if (
                actual_microusd < record.settled_microusd
                or actual_tokens < record.settled_tokens
                or actual_microusd > record.admitted_microusd
                or actual_tokens > record.admitted_tokens
            ):
                raise ModelProviderBudgetError(
                    "platform_model_budget_settlement_exceeds_reservation",
                    "model usage exceeds its reserved budget",
                )
            monthly, daily = self._locked_counters(db, record)
            self._require_reserved_counters(monthly, daily, record)
            monthly.reserved_microusd -= record.admitted_microusd
            monthly.settled_microusd += actual_microusd
            monthly.version += 1
            monthly.updated_at = at
            daily.reserved_tokens -= record.admitted_tokens
            daily.settled_tokens += actual_tokens
            daily.version += 1
            daily.updated_at = at
            record.settled_microusd = actual_microusd
            record.settled_tokens = actual_tokens
            record.released_microusd = record.admitted_microusd - actual_microusd
            record.released_tokens = record.admitted_tokens - actual_tokens
            record.status = "settled"
            record.updated_at = at
            record.version += 1
            db.flush()
            return _view(record)

    def apply_metered_usage(
        self,
        db: Session,
        *,
        reservation_id: UUID,
        tenant_id: UUID,
        run_id: UUID,
        actual_microusd: int,
        actual_tokens: int,
        now: datetime,
    ) -> ModelProviderBudgetReservationView:
        """Consume one metered delta inside the caller's billing transaction."""

        at = _aware(now)
        _positive_uuid(reservation_id, "reservation")
        _positive_uuid(tenant_id, "tenant")
        _positive_uuid(run_id, "run")
        _positive_amount(actual_microusd, "microusd")
        _positive_amount(actual_tokens, "tokens")
        record = self._locked_reservation(db, reservation_id)
        if (
            record.provider_id != _PROVIDER_ID
            or record.tenant_id != tenant_id
            or record.run_id != run_id
        ):
            raise ModelProviderBudgetError(
                "platform_model_budget_binding_invalid",
                "model budget reservation does not match the metered Run",
            )
        if record.status != "reserved" or at >= _stored_time(record.expires_at):
            raise ModelProviderBudgetError(
                "platform_model_budget_reservation_inactive",
                "model budget reservation is not active",
            )
        if (
            record.settled_microusd + actual_microusd > record.admitted_microusd
            or record.settled_tokens + actual_tokens > record.admitted_tokens
        ):
            raise ModelProviderBudgetError(
                "platform_model_budget_settlement_exceeds_reservation",
                "model usage exceeds its reserved budget",
            )
        record.settled_microusd += actual_microusd
        record.settled_tokens += actual_tokens
        record.updated_at = at
        record.version += 1
        db.flush()
        return _view(record)

    def release(
        self,
        *,
        reservation_id: UUID,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView:
        return self._release(reservation_id=reservation_id, expired=False, now=now)

    def recover_expired(
        self,
        *,
        limit: int = 100,
        now: datetime | None = None,
    ) -> tuple[ModelProviderBudgetReservationView, ...]:
        at = _aware(now or datetime.now(timezone.utc))
        if isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ModelProviderBudgetError(
                "platform_model_budget_request_invalid",
                "model budget recovery limit is invalid",
            )
        with self._sessions() as db:
            candidates = tuple(
                db.scalars(
                    sa.select(ModelProviderBudgetReservationRecord.id)
                    .where(
                        ModelProviderBudgetReservationRecord.provider_id == _PROVIDER_ID,
                        ModelProviderBudgetReservationRecord.status == "reserved",
                        ModelProviderBudgetReservationRecord.expires_at <= at,
                    )
                    .order_by(
                        ModelProviderBudgetReservationRecord.expires_at,
                        ModelProviderBudgetReservationRecord.id,
                    )
                    .limit(limit)
                )
            )
        recovered: list[ModelProviderBudgetReservationView] = []
        for reservation_id in candidates:
            try:
                recovered.append(
                    self._release(reservation_id=reservation_id, expired=True, now=at)
                )
            except ModelProviderBudgetError as error:
                if error.code != "platform_model_budget_reservation_inactive":
                    raise
        return tuple(recovered)

    def _release(
        self,
        *,
        reservation_id: UUID,
        expired: bool,
        now: datetime | None,
    ) -> ModelProviderBudgetReservationView:
        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(reservation_id, "reservation")
        target_status = "expired" if expired else "released"
        with self._sessions.begin() as db:
            record = self._locked_reservation(db, reservation_id)
            if record.status == target_status:
                return _view(record, replayed=True)
            if record.status != "reserved" or (expired and _stored_time(record.expires_at) > at):
                raise ModelProviderBudgetError(
                    "platform_model_budget_reservation_inactive",
                    "model budget reservation is not active",
                )
            monthly, daily = self._locked_counters(db, record)
            self._require_reserved_counters(monthly, daily, record)
            monthly.reserved_microusd -= record.admitted_microusd
            monthly.settled_microusd += record.settled_microusd
            monthly.version += 1
            monthly.updated_at = at
            daily.reserved_tokens -= record.admitted_tokens
            daily.settled_tokens += record.settled_tokens
            daily.version += 1
            daily.updated_at = at
            record.released_microusd = record.admitted_microusd - record.settled_microusd
            record.released_tokens = record.admitted_tokens - record.settled_tokens
            record.status = target_status
            record.updated_at = at
            record.version += 1
            db.flush()
            return _view(record)

    def _ensure_counters(
        self,
        db: Session,
        *,
        tenant_id: UUID,
        period_start: date,
        usage_date: date,
        now: datetime,
    ) -> None:
        values = (
            (
                ModelProviderMonthlyBudgetRecord,
                {
                    "provider_id": _PROVIDER_ID,
                    "period_start": period_start,
                    "reserved_microusd": 0,
                    "settled_microusd": 0,
                    "version": 1,
                    "updated_at": now,
                },
                ("provider_id", "period_start"),
            ),
            (
                ModelProviderTenantDailyUsageRecord,
                {
                    "tenant_id": tenant_id,
                    "provider_id": _PROVIDER_ID,
                    "usage_date": usage_date,
                    "reserved_tokens": 0,
                    "settled_tokens": 0,
                    "version": 1,
                    "updated_at": now,
                },
                ("tenant_id", "provider_id", "usage_date"),
            ),
        )
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            for model, row, keys in values:
                db.execute(
                    postgresql_insert(model)
                    .values(**row)
                    .on_conflict_do_nothing(index_elements=list(keys))
                )
            return
        for model, row, keys in values:
            identity = tuple(row[key] for key in keys)
            if db.get(model, identity if len(identity) > 1 else identity[0]) is None:
                db.add(model(**row))
        db.flush()

    @staticmethod
    def _locked_reservation(
        db: Session,
        reservation_id: UUID,
    ) -> ModelProviderBudgetReservationRecord:
        record = db.execute(
            sa.select(ModelProviderBudgetReservationRecord)
            .where(ModelProviderBudgetReservationRecord.id == reservation_id)
            .with_for_update()
        ).scalar_one_or_none()
        if record is None:
            raise ModelProviderBudgetError(
                "platform_model_budget_reservation_missing",
                "model budget reservation does not exist",
            )
        return record

    @staticmethod
    def _locked_counters(
        db: Session,
        record: ModelProviderBudgetReservationRecord,
    ) -> tuple[ModelProviderMonthlyBudgetRecord, ModelProviderTenantDailyUsageRecord]:
        monthly = db.execute(
            sa.select(ModelProviderMonthlyBudgetRecord)
            .where(
                ModelProviderMonthlyBudgetRecord.provider_id == record.provider_id,
                ModelProviderMonthlyBudgetRecord.period_start == record.period_start,
            )
            .with_for_update()
        ).scalar_one()
        daily = db.execute(
            sa.select(ModelProviderTenantDailyUsageRecord)
            .where(
                ModelProviderTenantDailyUsageRecord.tenant_id == record.tenant_id,
                ModelProviderTenantDailyUsageRecord.provider_id == record.provider_id,
                ModelProviderTenantDailyUsageRecord.usage_date == record.usage_date,
            )
            .with_for_update()
        ).scalar_one()
        return monthly, daily

    @staticmethod
    def _require_reserved_counters(
        monthly: ModelProviderMonthlyBudgetRecord,
        daily: ModelProviderTenantDailyUsageRecord,
        record: ModelProviderBudgetReservationRecord,
    ) -> None:
        if (
            monthly.reserved_microusd < record.admitted_microusd
            or daily.reserved_tokens < record.admitted_tokens
        ):
            raise ModelProviderBudgetError(
                "platform_model_budget_counter_corrupt",
                "model budget counter is inconsistent",
            )


def _view(
    record: ModelProviderBudgetReservationRecord,
    *,
    replayed: bool = False,
) -> ModelProviderBudgetReservationView:
    return ModelProviderBudgetReservationView(
        id=record.id,
        provider_id=record.provider_id,
        tenant_id=record.tenant_id,
        run_id=record.run_id,
        configuration_version=record.configuration_version,
        requested_microusd=record.requested_microusd,
        requested_tokens=record.requested_tokens,
        admitted_microusd=record.admitted_microusd,
        admitted_tokens=record.admitted_tokens,
        settled_microusd=record.settled_microusd,
        settled_tokens=record.settled_tokens,
        released_microusd=record.released_microusd,
        released_tokens=record.released_tokens,
        status=record.status,
        rejection_code=record.rejection_code,
        expires_at=_stored_time(record.expires_at),
        version=record.version,
        replayed=replayed,
    )


def _request_hash(**values: object) -> str:
    return sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _positive_uuid(value: UUID, label: str) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ModelProviderBudgetError(
            "platform_model_budget_request_invalid",
            f"model budget {label} is invalid",
        )


def _positive_amount(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1:
        raise ModelProviderBudgetError(
            "platform_model_budget_request_invalid",
            f"model budget {label} is invalid",
        )


def _operation_key(value: str) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value != value.strip()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise ModelProviderBudgetError(
            "platform_model_budget_request_invalid",
            "model budget operation key is invalid",
        )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ModelProviderBudgetError(
            "platform_model_budget_request_invalid",
            "model budget timestamp is invalid",
        )
    return value.astimezone(timezone.utc)


def _stored_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = [
    "ModelProviderBudgetAdmissionService",
    "ModelProviderBudgetError",
    "ModelProviderBudgetReservationView",
]
