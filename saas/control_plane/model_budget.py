"""Concurrent admission and settlement for Platform-managed model usage."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.query_context import query_name_scope
from saas.control_plane.model_gateway_evidence import (
    GatewayEvidenceView,
    GatewayRequestEvidence,
    GatewayRunRequestEvidence,
    decode_gateway_evidence,
    gateway_request_record,
    retain_gateway_evidence,
    retained_gateway_request,
)
from saas.control_plane.model_gateway_metering import gateway_call_reservation_id
from saas.control_plane.model_pricing import token_cost_microusd
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
    ModelProviderMonthlyBudgetRecord,
    ModelProviderTenantDailyUsageRecord,
    ModelTestFundingPolicyRecord,
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
    tenant_id: UUID | None
    run_id: UUID | None
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
    outcome_evidence_sha256: str | None = None
    purpose: str = "tenant_run"
    test_operation_id: UUID | None = None
    test_policy_version: int | None = None
    test_configuration_sha256: str | None = None


class ModelProviderBudgetAdmissionService:
    """Serialize global monthly spend and per-Tenant daily token authority."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        # Preserve the supplied session class and its authority-binding callbacks.
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
        gateway_request: GatewayRequestEvidence | None = None,
        gateway_call_id: UUID | None = None,
    ) -> ModelProviderBudgetReservationView:
        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(tenant_id, "tenant")
        _positive_uuid(run_id, "run")
        _operation_key(operation_key)
        _positive_amount(requested_microusd, "microusd")
        _positive_amount(requested_tokens, "tokens")
        if gateway_call_id is not None and (
            not isinstance(gateway_call_id, UUID)
            or not gateway_call_id.int
            or not isinstance(gateway_request, GatewayRunRequestEvidence)
            or operation_key != f"model-gateway:{run_id}:{gateway_call_id}"
        ):
            raise ModelProviderBudgetError(
                "platform_model_gateway_request_evidence_invalid",
                "Gateway call identity is invalid",
            )
        if gateway_request is not None and (
            not isinstance(gateway_request, GatewayRequestEvidence)
            or requested_tokens < gateway_request.output_token_limit
            or requested_microusd
            != token_cost_microusd(requested_tokens, gateway_request.model_price.reservation_rate)
            or (
                isinstance(gateway_request, GatewayRunRequestEvidence)
                and gateway_request.run_binding.run_id != str(run_id)
            )
        ):
            raise ModelProviderBudgetError(
                "platform_model_gateway_request_evidence_invalid",
                "Gateway cost binding is invalid",
            )
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
            **({"gateway_call_id": str(gateway_call_id)} if gateway_call_id is not None else {}),
            **(
                {"gateway_request": asdict(gateway_request)} if gateway_request is not None else {}
            ),
        )
        with self._sessions.begin() as db:
            # Serialize every Provider admission without granting Billing
            # access to the encrypted API-key column. PostgreSQL uses a
            # transaction-scoped advisory lock; SQLite tests serialize on the
            # single connection/file lock.
            lock_model_provider_budget(db)
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
            funding = latest_model_test_funding_policy(db)
            monthly_limit = configuration.monthly_budget_microusd
            if funding is not None:
                monthly_limit = min(monthly_limit, funding.monthly_budget_microusd)
            rejection_code: str | None = None
            if (
                monthly.reserved_microusd + monthly.settled_microusd + requested_microusd
                > monthly_limit
            ):
                rejection_code = "platform_model_monthly_budget_exhausted"
            elif (
                daily.reserved_tokens + daily.settled_tokens + requested_tokens
                > configuration.per_tenant_daily_token_limit
            ):
                rejection_code = "platform_model_tenant_daily_tokens_exhausted"
            admitted = rejection_code is None
            record = ModelProviderBudgetReservationRecord(
                id=gateway_call_reservation_id(run_id, gateway_call_id)
                if gateway_call_id is not None
                else uuid4(),
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
            if gateway_request is not None:
                retain_gateway_evidence(db, record, at=at, request=gateway_request)
            return _view(record)

    def reserve_platform_test(
        self,
        *,
        verification_id: UUID,
        actor_principal_id: UUID,
        configuration_sha256: str,
        operation_key: str,
        requested_microusd: int,
        requested_tokens: int,
        ttl: timedelta,
        expected_policy_version: int | None = None,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView:
        """Fund a trusted verification command, never a customer Run or invoice."""

        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(verification_id, "verification")
        _positive_uuid(actor_principal_id, "Staff principal")
        _positive_amount(requested_microusd, "microusd")
        _positive_amount(requested_tokens, "tokens")
        _operation_key(operation_key)
        if (
            not isinstance(configuration_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", configuration_sha256) is None
            or not timedelta(0) < ttl <= timedelta(minutes=5)
            or (
                expected_policy_version is not None
                and (type(expected_policy_version) is not int or expected_policy_version < 1)
            )
        ):
            raise ModelProviderBudgetError(
                "platform_model_budget_request_invalid", "Model test funding request is invalid"
            )
        request_hash = _request_hash(
            purpose="platform_test",
            verification_id=verification_id,
            actor_principal_id=actor_principal_id,
            configuration_sha256=configuration_sha256,
            operation_key=operation_key,
            requested_microusd=requested_microusd,
            requested_tokens=requested_tokens,
            **(
                {"expected_policy_version": expected_policy_version}
                if expected_policy_version is not None
                else {}
            ),
        )
        with (
            query_name_scope("saas.model_budget.reserve_platform_test"),
            self._sessions.begin() as db,
        ):
            lock_model_provider_budget(db)
            replays = db.scalars(
                sa.select(ModelProviderBudgetReservationRecord)
                .where(
                    ModelProviderBudgetReservationRecord.provider_id == _PROVIDER_ID,
                    sa.or_(
                        ModelProviderBudgetReservationRecord.operation_key == operation_key,
                        ModelProviderBudgetReservationRecord.test_operation_id == verification_id,
                    ),
                )
                .with_for_update()
                .limit(2)
            ).all()
            if len(replays) > 1:
                raise ModelProviderBudgetError(
                    "platform_model_budget_idempotency_conflict",
                    "Model test funding conflicts with its receipt",
                )
            if replays:
                replay = replays[0]
                if replay.request_hash != request_hash or replay.purpose != "platform_test":
                    raise ModelProviderBudgetError(
                        "platform_model_budget_idempotency_conflict",
                        "Model test funding conflicts with its receipt",
                    )
                return _view(replay, replayed=True)
            policy = latest_model_test_funding_policy(db)
            if policy is None or not policy.enabled:
                raise ModelProviderBudgetError(
                    "platform_model_test_funding_unavailable",
                    "Platform-funded model tests are unavailable",
                )
            if expected_policy_version is not None and policy.version != expected_policy_version:
                raise ModelProviderBudgetError(
                    "platform_model_test_funding_changed",
                    "Model test funding changed before reservation",
                )
            if (
                requested_microusd > policy.max_test_microusd
                or requested_tokens > policy.max_test_tokens
            ):
                raise ModelProviderBudgetError(
                    "platform_model_test_call_limit_exceeded",
                    "Model test exceeds its per-call funding limit",
                )
            period_start, usage_date = date(at.year, at.month, 1), at.date()
            self._ensure_counters(
                db, tenant_id=None, period_start=period_start, usage_date=usage_date, now=at
            )
            monthly = db.scalar(
                sa.select(ModelProviderMonthlyBudgetRecord)
                .where(
                    ModelProviderMonthlyBudgetRecord.provider_id == _PROVIDER_ID,
                    ModelProviderMonthlyBudgetRecord.period_start == period_start,
                )
                .with_for_update()
            )
            assert monthly is not None
            row = ModelProviderBudgetReservationRecord
            pending = row.status.in_(("reserved", "in_flight", "uncertain"))
            spent, tokens, attempts = db.execute(
                sa.select(
                    sa.func.coalesce(
                        sa.func.sum(
                            sa.case((pending, row.admitted_microusd), else_=row.settled_microusd)
                        ),
                        0,
                    ),
                    sa.func.coalesce(
                        sa.func.sum(
                            sa.case((pending, row.admitted_tokens), else_=row.settled_tokens)
                        ),
                        0,
                    ),
                    sa.func.count(row.id),
                ).where(
                    row.provider_id == _PROVIDER_ID,
                    row.purpose == "platform_test",
                    row.usage_date == usage_date,
                    row.admitted_microusd > 0,
                )
            ).one()
            legacy_limit = db.scalar(
                sa.select(ModelProviderConfigurationRecord.monthly_budget_microusd).where(
                    ModelProviderConfigurationRecord.provider_id == _PROVIDER_ID
                )
            )
            monthly_limit = (
                min(policy.monthly_budget_microusd, legacy_limit)
                if legacy_limit is not None
                else policy.monthly_budget_microusd
            )
            rejection_code = (
                "platform_model_monthly_budget_exhausted"
                if monthly.reserved_microusd + monthly.settled_microusd + requested_microusd
                > monthly_limit
                else "platform_model_test_daily_budget_exhausted"
                if spent + requested_microusd > policy.daily_test_budget_microusd
                else "platform_model_test_daily_tokens_exhausted"
                if tokens + requested_tokens > policy.daily_test_token_limit
                else "platform_model_test_daily_attempts_exhausted"
                if attempts >= policy.daily_test_attempt_limit
                else None
            )
            admitted = rejection_code is None
            record = row(
                id=uuid4(),
                provider_id=_PROVIDER_ID,
                tenant_id=None,
                run_id=None,
                purpose="platform_test",
                test_operation_id=verification_id,
                test_actor_principal_id=actor_principal_id,
                test_policy_version=policy.version,
                test_configuration_sha256=configuration_sha256,
                operation_key=operation_key,
                request_hash=request_hash,
                configuration_version=policy.version,
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
                monthly.updated_at, monthly.version = at, monthly.version + 1
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
            if record.purpose != "tenant_run" or gateway_request_record(db, record.id) is not None:
                raise ModelProviderBudgetError(
                    "platform_model_budget_outcome_required",
                    "Platform test settlement requires attempt evidence",
                )
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
            if daily is not None:
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

    def begin_attempt(
        self, *, reservation_id: UUID, now: datetime | None = None
    ) -> ModelProviderBudgetReservationView:
        """Commit the single-attempt fence before sending any inference bytes."""

        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(reservation_id, "reservation")
        with (
            query_name_scope("saas.model_budget.begin_inference_attempt"),
            self._sessions.begin() as db,
        ):
            lock_model_provider_budget(db)
            record = self._locked_reservation(db, reservation_id)
            if record.purpose == "platform_test":
                policy = latest_model_test_funding_policy(db)
                if (
                    policy is None
                    or not policy.enabled
                    or policy.version != record.test_policy_version
                ):
                    raise ModelProviderBudgetError(
                        "platform_model_test_funding_changed",
                        "Model test funding changed before inference",
                    )
            if record.status in {"in_flight", "uncertain"}:
                raise ModelProviderBudgetError(
                    "platform_model_budget_attempt_already_started",
                    "Inference attempt already started",
                )
            if (
                record.status != "reserved"
                or at >= _stored_time(record.expires_at)
                or record.settled_microusd != 0
                or record.settled_tokens != 0
            ):
                raise ModelProviderBudgetError(
                    "platform_model_budget_reservation_inactive",
                    "Model budget reservation is not active",
                )
            request_row = gateway_request_record(db, record.id)
            if request_row is not None:
                from saas.control_plane.model_disablement import publication_is_disabled

                bound = retained_gateway_request(request_row, record)
                if isinstance(bound, GatewayRunRequestEvidence) and (
                    record.tenant_id is None
                    or publication_is_disabled(
                        db,
                        tenant_id=record.tenant_id,
                        public_model_id=bound.public_model_id,
                        wire_api=bound.wire_api,
                        generation=bound.run_binding.publication_generation,
                    )
                ):
                    raise ModelProviderBudgetError(
                        "platform_model_disabled", "Model authority changed before inference"
                    )
            record.status, record.updated_at = "in_flight", at
            record.version += 1
            retain_gateway_evidence(db, record, at=at)
            db.flush()
            return _view(record)

    def mark_uncertain(
        self,
        *,
        reservation_id: UUID,
        now: datetime | None = None,
        reason: str = "provider_outcome_unknown",
    ) -> ModelProviderBudgetReservationView:
        """Retain the full hold; expiry and ordinary release cannot settle unknown costs."""

        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(reservation_id, "reservation")
        if not isinstance(reason, str) or reason not in {
            "provider_outcome_unknown",
            "provider_rejected",
            "provider_unreachable",
            "stream_incomplete",
            "settlement_unavailable",
        }:
            raise ModelProviderBudgetError(
                "platform_model_budget_outcome_invalid", "Invalid outcome reason"
            )
        with (
            query_name_scope("saas.model_budget.retain_uncertain_inference"),
            self._sessions.begin() as db,
        ):
            record = self._locked_reservation(db, reservation_id)
            if record.status == "uncertain":
                return _view(record, replayed=True)
            if record.status != "in_flight":
                raise ModelProviderBudgetError(
                    "platform_model_budget_reservation_inactive",
                    "Inference attempt is not pending",
                )
            record.status, record.updated_at = "uncertain", at
            record.version += 1
            retain_gateway_evidence(db, record, at=at, reason=reason)
            db.flush()
            return _view(record)

    def resolve_attempt(
        self,
        *,
        reservation_id: UUID,
        actual_microusd: int,
        actual_tokens: int,
        evidence_sha256: str | None,
        now: datetime | None = None,
        gateway_usage: ModelTokenUsage | None = None,
    ) -> ModelProviderBudgetReservationView:
        """Resolve one sent attempt from trusted usage or authoritative no-usage evidence."""

        at = _aware(now or datetime.now(timezone.utc))
        _positive_uuid(reservation_id, "reservation")
        if (
            (evidence_sha256 is None and gateway_usage is None)
            or (
                evidence_sha256 is not None
                and (
                    not isinstance(evidence_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", evidence_sha256) is None
                )
            )
            or type(actual_microusd) is not int
            or type(actual_tokens) is not int
            or not 0 <= actual_microusd <= (1 << 63) - 1
            or not 0 <= actual_tokens <= (1 << 63) - 1
            or (actual_microusd == 0) != (actual_tokens == 0)
        ):
            raise ModelProviderBudgetError(
                "platform_model_budget_outcome_invalid", "Inference outcome evidence is invalid"
            )
        with (
            query_name_scope("saas.model_budget.resolve_inference_outcome"),
            self._sessions.begin() as db,
        ):
            record = self._locked_reservation(db, reservation_id)
            request = gateway_request_record(db, reservation_id)
            if gateway_usage is not None:
                try:
                    if request is None or not isinstance(gateway_usage, ModelTokenUsage):
                        raise ValueError("Missing gateway request")
                    bound = retained_gateway_request(request, record)
                    if (
                        gateway_usage.total_tokens != actual_tokens
                        or gateway_usage.output_tokens > bound.output_token_limit
                        or bound.model_price.cost(
                            gateway_usage, at=_stored_time(record.created_at)
                        )
                        != actual_microusd
                    ):
                        raise ValueError("Invalid gateway usage binding")
                except (ValueError, TypeError, KeyError):
                    raise ModelProviderBudgetError(
                        "platform_model_budget_outcome_invalid",
                        "Gateway usage evidence is invalid",
                    ) from None
            if record.status in {"settled", "released"}:
                if gateway_usage is not None:
                    receipt = db.scalar(
                        sa.select(ModelGatewayEvidenceRecord).where(
                            ModelGatewayEvidenceRecord.reservation_id == record.id,
                            ModelGatewayEvidenceRecord.phase == record.status,
                        )
                    )
                    if receipt is None or json.loads(receipt.canonical_evidence)[
                        "usage"
                    ] != asdict(gateway_usage):
                        raise ModelProviderBudgetError(
                            "platform_model_budget_settlement_conflict",
                            "Gateway usage conflicts with its receipt",
                        )
                    evidence_sha256 = evidence_sha256 or receipt.evidence_sha256
                if (
                    record.outcome_evidence_sha256 != evidence_sha256
                    or record.settled_microusd != actual_microusd
                    or record.settled_tokens != actual_tokens
                ):
                    raise ModelProviderBudgetError(
                        "platform_model_budget_settlement_conflict",
                        "Inference outcome conflicts with its receipt",
                    )
                return _view(record, replayed=True)
            if request is not None and (gateway_usage is None or evidence_sha256 is not None):
                raise ModelProviderBudgetError(
                    "platform_model_budget_outcome_invalid",
                    "Gateway requires normalized usage evidence",
                )
            pre_egress_zero = (
                record.purpose == "platform_test"
                and record.status == "reserved"
                and actual_tokens == 0
            )
            if record.status not in {"in_flight", "uncertain"} and not pre_egress_zero:
                raise ModelProviderBudgetError(
                    "platform_model_budget_reservation_inactive",
                    "No sent inference attempt awaits resolution",
                )
            if not (
                record.settled_microusd <= actual_microusd <= record.admitted_microusd
                and record.settled_tokens <= actual_tokens <= record.admitted_tokens
            ):
                raise ModelProviderBudgetError(
                    "platform_model_budget_settlement_exceeds_reservation",
                    "Inference outcome exceeds its hold",
                )
            monthly, daily = self._locked_counters(db, record)
            self._require_reserved_counters(monthly, daily, record)
            monthly.reserved_microusd -= record.admitted_microusd
            monthly.settled_microusd += actual_microusd
            if daily is not None:
                daily.reserved_tokens -= record.admitted_tokens
                daily.settled_tokens += actual_tokens
            for counter in (monthly, daily) if daily is not None else (monthly,):
                counter.updated_at, counter.version = at, counter.version + 1
            record.settled_microusd, record.settled_tokens = actual_microusd, actual_tokens
            record.released_microusd = record.admitted_microusd - actual_microusd
            record.released_tokens = record.admitted_tokens - actual_tokens
            record.status = "settled" if actual_tokens else "released"
            record.outcome_evidence_sha256 = evidence_sha256
            record.updated_at, record.version = at, record.version + 1
            retain_gateway_evidence(db, record, at=at, usage=gateway_usage)
            db.flush()
            return _view(record)

    def gateway_evidence(
        self,
        *,
        reservation_id: UUID,
        tenant_id: UUID,
        run_id: UUID,
    ) -> tuple[GatewayEvidenceView, ...]:
        for value in (reservation_id, tenant_id, run_id):
            _positive_uuid(value, "evidence scope")
        with query_name_scope("saas.model_budget.read_gateway_evidence"), self._sessions() as db:
            record = db.get(ModelProviderBudgetReservationRecord, reservation_id)
            if record is None or record.tenant_id != tenant_id or record.run_id != run_id:
                raise ModelProviderBudgetError(
                    "platform_model_budget_binding_invalid", "Gateway evidence scope is invalid"
                )
            rows = db.scalars(
                sa.select(ModelGatewayEvidenceRecord)
                .where(
                    ModelGatewayEvidenceRecord.reservation_id == record.id,
                    ModelGatewayEvidenceRecord.tenant_id == tenant_id,
                )
                .order_by(ModelGatewayEvidenceRecord.budget_version)
            ).all()
            try:
                for row in rows:
                    decode_gateway_evidence(row, record)
            except (ValueError, KeyError, TypeError):
                raise ModelProviderBudgetError(
                    "platform_model_gateway_evidence_drift", "Gateway evidence digest changed"
                ) from None
            return tuple(
                GatewayEvidenceView(
                    row.id,
                    row.reservation_id,
                    row.phase,
                    row.canonical_evidence,
                    row.evidence_sha256,
                )
                for row in rows
            )

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
            or record.purpose != "tenant_run"
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
            if daily is not None:
                daily.reserved_tokens -= record.admitted_tokens
                daily.settled_tokens += record.settled_tokens
                daily.version += 1
                daily.updated_at = at
            record.released_microusd = record.admitted_microusd - record.settled_microusd
            record.released_tokens = record.admitted_tokens - record.settled_tokens
            record.status = target_status
            record.updated_at = at
            record.version += 1
            retain_gateway_evidence(db, record, at=at, reason="not_sent")
            db.flush()
            return _view(record)

    def _ensure_counters(
        self,
        db: Session,
        *,
        tenant_id: UUID | None,
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
            for model, row, keys in values[:1] if tenant_id is None else values:
                db.execute(
                    postgresql_insert(model)
                    .values(**row)
                    .on_conflict_do_nothing(index_elements=list(keys))
                )
            return
        for model, row, keys in values[:1] if tenant_id is None else values:
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
    ) -> tuple[ModelProviderMonthlyBudgetRecord, ModelProviderTenantDailyUsageRecord | None]:
        monthly = db.execute(
            sa.select(ModelProviderMonthlyBudgetRecord)
            .where(
                ModelProviderMonthlyBudgetRecord.provider_id == record.provider_id,
                ModelProviderMonthlyBudgetRecord.period_start == record.period_start,
            )
            .with_for_update()
        ).scalar_one()
        if record.purpose == "platform_test":
            return monthly, None
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
        daily: ModelProviderTenantDailyUsageRecord | None,
        record: ModelProviderBudgetReservationRecord,
    ) -> None:
        if monthly.reserved_microusd < record.admitted_microusd or (
            daily is not None and daily.reserved_tokens < record.admitted_tokens
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
        outcome_evidence_sha256=record.outcome_evidence_sha256,
        purpose=record.purpose,
        test_operation_id=record.test_operation_id,
        test_policy_version=record.test_policy_version,
        test_configuration_sha256=record.test_configuration_sha256,
    )


def lock_model_provider_budget(db: Session) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            sa.select(
                sa.func.pg_advisory_xact_lock(
                    sa.func.hashtextextended("platform-model-budget:deepseek", 0)
                )
            )
        )


def latest_model_test_funding_policy(db: Session) -> ModelTestFundingPolicyRecord | None:
    return db.scalar(
        sa.select(ModelTestFundingPolicyRecord)
        .where(ModelTestFundingPolicyRecord.provider_id == _PROVIDER_ID)
        .order_by(ModelTestFundingPolicyRecord.version.desc())
        .limit(1)
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
