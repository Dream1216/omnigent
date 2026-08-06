"""Execution-authority-bound machine metering for the P6 billing ledger."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.billing import BillingControlPlane
from saas.control_plane.billing_models import (
    BillingMeteringReceiptRecord,
    BillingSubscriptionRecord,
    PricingSnapshotRecord,
    UsageEventRecord,
)
from saas.control_plane.certificate_models import RunnerCertificateRecord
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunDispatchRecord,
    RunnerRegistrationRecord,
)

_ACTION = "billing.usage.record"
_ACTIVE_RUN_STATUSES = frozenset(
    {"leased", "starting", "running", "waiting_input", "waiting_approval", "cancelling"}
)
_ACTIVE_SUBSCRIPTION_STATUSES = frozenset({"trialing", "active"})
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_SENSITIVE_ATTRIBUTE_TOKENS = frozenset(
    {"prompt", "code", "secret", "token", "password", "credential", "authorization"}
)
_USAGE_ATTRIBUTE_KEYS = frozenset(
    {
        "batch",
        "cache_hit",
        "model",
        "model_version",
        "operation",
        "provider_region",
        "request_class",
        "service_tier",
        "tool_kind",
    }
)


class BillingMeteringError(RuntimeError):
    """Stable, transport-neutral machine metering failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class MeteredUsage:
    receipt_id: UUID
    usage_event_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    run_id: UUID
    runner_id: UUID
    pricing_snapshot_id: UUID
    meter: str
    quantity: Decimal
    unit: str
    currency: str
    customer_charge_minor: int
    occurred_at: datetime
    recorded_at: datetime
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class _RunAuthority:
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    session_id: UUID | None
    created_by: UUID
    status: str
    fence_token: int
    lease_owner: str | None
    lease_expires_at: datetime | None
    created_at: datetime


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _time(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BillingMeteringError("metering_time_invalid", f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _text(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise BillingMeteringError("metering_value_invalid", f"{field} is invalid")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise BillingMeteringError("metering_value_invalid", f"{field} is invalid")
    return normalized


def _quantity(value: Decimal | str | int) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise BillingMeteringError("metering_quantity_invalid", "quantity is invalid") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise BillingMeteringError("metering_quantity_invalid", "quantity is invalid")
    exponent = parsed.as_tuple().exponent
    if not isinstance(exponent, int) or exponent < -12:
        raise BillingMeteringError("metering_quantity_invalid", "quantity is invalid")
    if parsed.adjusted() > 25:
        raise BillingMeteringError("metering_quantity_invalid", "quantity is oversized")
    return parsed


def _attributes(attributes: dict[str, object]) -> dict[str, object]:
    if not isinstance(attributes, dict) or len(attributes) > 32:
        raise BillingMeteringError("metering_attributes_invalid", "attributes are invalid")
    normalized: dict[str, object] = {}
    for key, value in sorted(attributes.items()):
        clean_key = _text(key, "attribute_key", 64)
        lowered = clean_key.lower()
        if any(token in lowered for token in _SENSITIVE_ATTRIBUTE_TOKENS):
            raise BillingMeteringError(
                "metering_attributes_sensitive", "attributes cannot contain sensitive content"
            )
        if lowered not in _USAGE_ATTRIBUTE_KEYS:
            raise BillingMeteringError(
                "metering_attributes_invalid", "attribute is not in the metering allowlist"
            )
        if not isinstance(value, (str, int, bool, type(None))) or (
            isinstance(value, str) and len(value) > 256
        ):
            raise BillingMeteringError("metering_attributes_invalid", "attributes are invalid")
        normalized[clean_key] = value
    if len(json.dumps(normalized, sort_keys=True, separators=(",", ":"))) > 4096:
        raise BillingMeteringError("metering_attributes_invalid", "attributes are oversized")
    return normalized


def _request_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode("utf-8")).hexdigest()


def _capability_hash(token: str) -> str:
    return sha256(_text(token, "capability_token", 512).encode("utf-8")).hexdigest()


class BillingMeteringAuthority:
    """Persist one Usage fact only after revalidating the live execution authority."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record_usage(
        self,
        *,
        runner_id: UUID,
        certificate_fingerprint_sha256: str,
        capability_token: str,
        run_id: UUID,
        meter: str,
        quantity: Decimal | str | int,
        unit: str,
        provider: str,
        provider_request_id: str,
        idempotency_key: str,
        occurred_at: datetime,
        attributes: dict[str, object] | None = None,
        now: datetime | None = None,
    ) -> MeteredUsage:
        checked_at = _time(now or datetime.now(timezone.utc), "now")
        happened = _time(occurred_at, "occurred_at")
        fingerprint = certificate_fingerprint_sha256.strip().lower()
        if _HEX_SHA256.fullmatch(fingerprint) is None:
            raise BillingMeteringError(
                "metering_certificate_invalid", "certificate fingerprint is invalid"
            )
        capability_digest = _capability_hash(capability_token)
        clean_meter = _text(meter, "meter", 128)
        units = _quantity(quantity)
        clean_unit = _text(unit, "unit", 64)
        clean_provider = _text(provider, "provider", 64)
        provider_request = _text(provider_request_id, "provider_request_id", 256)
        key = _text(idempotency_key, "idempotency_key", 128)
        clean_attributes = _attributes(attributes or {})
        if happened > checked_at + timedelta(minutes=5):
            raise BillingMeteringError(
                "metering_time_invalid", "occurred_at is beyond the allowed clock skew"
            )

        with self._session_factory.begin() as db:
            self._set_exact_identity_context(
                db,
                fingerprint=fingerprint,
                capability_digest=capability_digest,
                idempotency_key=key,
                provider=clean_provider,
                provider_request_id=provider_request,
                meter=clean_meter,
            )
            runner = db.scalar(
                sa.select(RunnerRegistrationRecord)
                .where(RunnerRegistrationRecord.id == runner_id)
                .with_for_update()
            )
            certificate = db.scalar(
                sa.select(RunnerCertificateRecord)
                .where(
                    RunnerCertificateRecord.runner_id == runner_id,
                    RunnerCertificateRecord.fingerprint_sha256 == fingerprint,
                    RunnerCertificateRecord.purpose == "billing_metering",
                )
                .with_for_update()
            )
            capability = db.scalar(
                sa.select(CapabilityTokenRecord)
                .where(CapabilityTokenRecord.token_hash == capability_digest)
                .with_for_update()
            )
            self._require_machine_identity(
                runner=runner,
                certificate=certificate,
                capability=capability,
                runner_id=runner_id,
                run_id=run_id,
                meter=clean_meter,
                checked_at=checked_at,
            )
            assert runner is not None
            assert certificate is not None
            assert capability is not None

            apply_rls_context(
                db,
                RlsContext(tenant_id=capability.tenant_id, space_id=capability.space_id),
            )
            run = self._run_authority(db, run_id)
            self._set_authoritative_usage_context(db, run)
            dispatch = db.scalar(
                sa.select(RunDispatchRecord)
                .where(RunDispatchRecord.run_id == run_id)
                .with_for_update()
            )
            self._require_execution_authority(
                runner=runner,
                certificate=certificate,
                capability=capability,
                run=run,
                dispatch=dispatch,
                runner_id=runner_id,
                run_id=run_id,
                happened=happened,
                checked_at=checked_at,
            )
            BillingControlPlane._transaction_locks(
                db,
                f"billing-metering-idempotency:{capability.tenant_id}:{key}",
                (
                    f"billing-provider-request:{capability.tenant_id}:{clean_provider}:"
                    f"{provider_request}:{clean_meter}"
                ),
            )
            pricing = self._effective_pricing(
                db,
                tenant_id=capability.tenant_id,
                happened=happened,
            )
            charge = self._charge(
                pricing=pricing,
                meter=clean_meter,
                quantity=units,
                unit=clean_unit,
            )
            payload: dict[str, object] = {
                "tenant_id": str(capability.tenant_id),
                "space_id": str(run.space_id),
                "project_id": str(run.project_id),
                "session_id": str(run.session_id) if run.session_id else None,
                "run_id": str(run_id),
                "user_id": str(run.created_by),
                "runner_id": str(runner_id),
                "pricing_snapshot_id": str(pricing.id),
                "meter": clean_meter,
                "quantity": str(units),
                "unit": clean_unit,
                "provider": clean_provider,
                "provider_request_id": provider_request,
                "occurred_at": happened.isoformat(),
                "attributes": clean_attributes,
            }
            digest = _request_hash(payload)
            receipt = db.scalar(
                sa.select(BillingMeteringReceiptRecord).where(
                    BillingMeteringReceiptRecord.tenant_id == capability.tenant_id,
                    BillingMeteringReceiptRecord.idempotency_key == key,
                )
            )
            if receipt is not None:
                if receipt.request_hash != digest:
                    raise BillingMeteringError(
                        "metering_idempotency_conflict", "idempotency key was already used"
                    )
                usage = db.get(UsageEventRecord, receipt.usage_event_id)
                if usage is None:
                    raise BillingMeteringError(
                        "metering_invariant_broken", "metering receipt is orphaned"
                    )
                return self._view(receipt, usage, replayed=True)

            duplicate = db.scalar(
                sa.select(UsageEventRecord).where(
                    UsageEventRecord.tenant_id == capability.tenant_id,
                    UsageEventRecord.provider == clean_provider,
                    UsageEventRecord.provider_request_id == provider_request,
                    UsageEventRecord.meter == clean_meter,
                )
            )
            if duplicate is not None:
                raise BillingMeteringError(
                    "metering_provider_request_duplicate",
                    "provider request and meter already exist",
                )

            usage = UsageEventRecord(
                id=uuid4(),
                tenant_id=capability.tenant_id,
                space_id=run.space_id,
                project_id=run.project_id,
                session_id=run.session_id,
                run_id=run_id,
                user_id=run.created_by,
                meter=clean_meter,
                quantity=units,
                unit=clean_unit,
                provider=clean_provider,
                provider_request_id=provider_request,
                idempotency_key=key,
                pricing_snapshot_id=pricing.id,
                currency=pricing.currency,
                customer_charge_minor=charge,
                attributes=clean_attributes,
                occurred_at=happened,
            )
            db.add(usage)
            db.flush()
            receipt = BillingMeteringReceiptRecord(
                id=uuid4(),
                tenant_id=capability.tenant_id,
                space_id=run.space_id,
                project_id=run.project_id,
                run_id=run_id,
                usage_event_id=usage.id,
                runner_id=runner_id,
                runner_connection_generation=runner.connection_generation,
                runner_certificate_id=certificate.id,
                certificate_fingerprint_sha256=fingerprint,
                capability_id=capability.id,
                dispatch_generation=capability.dispatch_generation,
                fence_token=capability.fence_token,
                idempotency_key=key,
                request_hash=digest,
            )
            db.add(receipt)
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    tenant_id=capability.tenant_id,
                    aggregate_type="billing",
                    aggregate_key=str(usage.id),
                    event_type="billing.usage.recorded",
                    payload={
                        **payload,
                        "usage_event_id": str(usage.id),
                        "metering_receipt_id": str(receipt.id),
                        "capability_id": str(capability.id),
                        "runner_connection_generation": runner.connection_generation,
                        "dispatch_generation": capability.dispatch_generation,
                        "fence_token": capability.fence_token,
                        "currency": usage.currency,
                        "customer_charge_minor": charge,
                    },
                    idempotency_key=scoped_idempotency_key(
                        "billing-metering", capability.tenant_id, key
                    ),
                    request_hash=digest,
                    attempt_count=0,
                    created_at=checked_at,
                )
            )
            return self._view(receipt, usage)

    @staticmethod
    def _set_exact_identity_context(
        db: Session,
        *,
        fingerprint: str,
        capability_digest: str,
        idempotency_key: str,
        provider: str,
        provider_request_id: str,
        meter: str,
    ) -> None:
        if db.get_bind().dialect.name != "postgresql":
            return
        db.execute(
            sa.text(
                "SELECT "
                "set_config('app.presented_certificate_fingerprint', :fingerprint, true), "
                "set_config('app.presented_certificate_purpose', 'billing_metering', true), "
                "set_config('app.capability_token_hash', :capability, true), "
                "set_config('app.metering_idempotency_key', :idempotency, true), "
                "set_config('app.metering_provider', :provider, true), "
                "set_config('app.metering_provider_request_id', :provider_request, true), "
                "set_config('app.metering_meter', :meter, true)"
            ),
            {
                "fingerprint": fingerprint,
                "capability": capability_digest,
                "idempotency": idempotency_key,
                "provider": provider,
                "provider_request": provider_request_id,
                "meter": meter,
            },
        )

    @staticmethod
    def _require_machine_identity(
        *,
        runner: RunnerRegistrationRecord | None,
        certificate: RunnerCertificateRecord | None,
        capability: CapabilityTokenRecord | None,
        runner_id: UUID,
        run_id: UUID,
        meter: str,
        checked_at: datetime,
    ) -> None:
        if runner is None or certificate is None:
            raise BillingMeteringError(
                "metering_certificate_denied", "Runner certificate is not authorized"
            )
        if capability is None:
            raise BillingMeteringError("metering_capability_invalid", "capability is invalid")
        if runner.status not in {"online", "draining"}:
            raise BillingMeteringError("metering_runner_unavailable", "Runner is unavailable")
        accepted_certificate = certificate.status == "active" or (
            certificate.status == "retiring"
            and certificate.retire_at is not None
            and checked_at < _as_utc(certificate.retire_at)
        )
        if not (
            accepted_certificate
            and _as_utc(certificate.certificate_not_before)
            <= checked_at
            < _as_utc(certificate.certificate_not_after)
            and certificate.runner_id == runner_id
            and certificate.runner_connection_generation == runner.connection_generation
        ):
            raise BillingMeteringError(
                "metering_certificate_denied", "Runner certificate is not authorized"
            )
        if capability.revoked_at is not None or _as_utc(capability.expires_at) <= checked_at:
            raise BillingMeteringError(
                "metering_capability_expired", "capability is expired or revoked"
            )
        if capability.runner_id != runner_id or capability.run_id != run_id:
            raise BillingMeteringError(
                "metering_capability_binding_invalid", "capability binding is invalid"
            )
        if _ACTION not in capability.allowed_actions:
            raise BillingMeteringError(
                "metering_capability_action_denied", "capability action is denied"
            )
        BillingMeteringAuthority._require_meter_scope(capability.resource_scope, meter)

    @staticmethod
    def _set_authoritative_usage_context(db: Session, run: _RunAuthority) -> None:
        if db.get_bind().dialect.name != "postgresql":
            return
        db.execute(
            sa.text(
                "SELECT set_config('app.metering_session_id', :session_id, true), "
                "set_config('app.metering_user_id', :user_id, true)"
            ),
            {
                "session_id": str(run.session_id) if run.session_id else "",
                "user_id": str(run.created_by),
            },
        )

    @staticmethod
    def _require_meter_scope(resource_scope: dict[str, str], meter: str) -> None:
        exact = resource_scope.get("billing_meter")
        multiple = resource_scope.get("billing_meters")
        if exact is not None and multiple is not None:
            raise BillingMeteringError(
                "metering_capability_scope_invalid", "capability meter scope is ambiguous"
            )
        if exact is not None:
            allowed = {_text(exact, "billing_meter", 128)}
        elif multiple is not None:
            values = multiple.split(",")
            if not 1 <= len(values) <= 32:
                raise BillingMeteringError(
                    "metering_capability_scope_invalid", "capability meter scope is invalid"
                )
            allowed = {_text(value, "billing_meter", 128) for value in values}
            if len(allowed) != len(values):
                raise BillingMeteringError(
                    "metering_capability_scope_invalid", "capability meter scope is invalid"
                )
        else:
            raise BillingMeteringError(
                "metering_capability_scope_denied", "capability has no billing meter scope"
            )
        if meter not in allowed:
            raise BillingMeteringError(
                "metering_capability_scope_denied", "meter is outside capability scope"
            )

    @staticmethod
    def _run_authority(db: Session, run_id: UUID) -> _RunAuthority:
        row = db.execute(
            sa.select(
                RunRecord.tenant_id,
                RunRecord.space_id,
                RunRecord.project_id,
                RunRecord.session_id,
                RunRecord.created_by,
                RunRecord.status,
                RunRecord.fence_token,
                RunRecord.lease_owner,
                RunRecord.lease_expires_at,
                RunRecord.created_at,
            )
            .where(RunRecord.id == run_id)
            .with_for_update()
        ).one_or_none()
        if row is None:
            raise BillingMeteringError("metering_run_unavailable", "Run is unavailable")
        return _RunAuthority(*row)

    @staticmethod
    def _require_execution_authority(
        *,
        runner: RunnerRegistrationRecord,
        certificate: RunnerCertificateRecord,
        capability: CapabilityTokenRecord,
        run: _RunAuthority,
        dispatch: RunDispatchRecord | None,
        runner_id: UUID,
        run_id: UUID,
        happened: datetime,
        checked_at: datetime,
    ) -> None:
        authoritative_scope = {
            "tenant_id": str(run.tenant_id),
            "space_id": str(run.space_id),
            "project_id": str(run.project_id),
            "run_id": str(run_id),
            "runner_id": str(runner_id),
        }
        if any(
            capability.resource_scope.get(key) != value
            for key, value in authoritative_scope.items()
        ):
            raise BillingMeteringError(
                "metering_capability_scope_denied", "capability execution scope is stale"
            )
        if (
            capability.tenant_id != run.tenant_id
            or capability.space_id != run.space_id
            or capability.project_id != run.project_id
            or capability.runner_connection_generation != runner.connection_generation
            or certificate.runner_connection_generation != runner.connection_generation
        ):
            raise BillingMeteringError(
                "metering_capability_binding_invalid", "capability binding is stale"
            )
        if (
            dispatch is None
            or dispatch.status != "leased"
            or dispatch.selected_runner_id != runner_id
            or dispatch.dispatch_generation != capability.dispatch_generation
        ):
            raise BillingMeteringError(
                "metering_dispatch_stale", "Run dispatch is no longer authoritative"
            )
        if (
            run.status not in _ACTIVE_RUN_STATUSES
            or run.fence_token != capability.fence_token
            or run.lease_owner != str(runner_id)
            or run.lease_expires_at is None
            or _as_utc(run.lease_expires_at) <= checked_at
        ):
            raise BillingMeteringError(
                "metering_fence_stale", "Run fence or lease is no longer authoritative"
            )
        if happened < _as_utc(run.created_at) - timedelta(minutes=5):
            raise BillingMeteringError(
                "metering_time_invalid", "occurred_at predates the authoritative Run"
            )

    @staticmethod
    def _effective_pricing(
        db: Session, *, tenant_id: UUID, happened: datetime
    ) -> PricingSnapshotRecord:
        subscription = db.scalar(
            sa.select(BillingSubscriptionRecord)
            .where(BillingSubscriptionRecord.tenant_id == tenant_id)
            .with_for_update()
        )
        if subscription is None or subscription.status not in _ACTIVE_SUBSCRIPTION_STATUSES:
            raise BillingMeteringError(
                "metering_subscription_unavailable", "subscription does not accept usage"
            )
        candidates = list(
            db.scalars(
                sa.select(PricingSnapshotRecord)
                .where(
                    PricingSnapshotRecord.tenant_id == tenant_id,
                    PricingSnapshotRecord.plan_key == subscription.plan_key,
                    PricingSnapshotRecord.effective_from <= happened,
                    sa.or_(
                        PricingSnapshotRecord.effective_until.is_(None),
                        PricingSnapshotRecord.effective_until > happened,
                    ),
                )
                .order_by(PricingSnapshotRecord.version.desc())
                .limit(2)
            )
        )
        if len(candidates) != 1:
            raise BillingMeteringError(
                "metering_pricing_unavailable",
                "exactly one effective pricing snapshot is required",
            )
        return candidates[0]

    @staticmethod
    def _charge(
        *, pricing: PricingSnapshotRecord, meter: str, quantity: Decimal, unit: str
    ) -> int:
        rate = pricing.rates.get(meter)
        if not isinstance(rate, dict) or rate.get("unit") != unit:
            raise BillingMeteringError("metering_rate_missing", "meter rate is unavailable")
        try:
            unit_size = Decimal(cast(str, rate["unit_size"]))
            minor_per_unit = cast(int, rate["minor_per_unit"])
        except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
            raise BillingMeteringError("metering_rate_invalid", "meter rate is invalid") from exc
        if unit_size <= 0 or isinstance(minor_per_unit, bool) or minor_per_unit <= 0:
            raise BillingMeteringError("metering_rate_invalid", "meter rate is invalid")
        charge = int(
            (quantity / unit_size * minor_per_unit).to_integral_value(rounding=ROUND_CEILING)
        )
        if charge <= 0:
            raise BillingMeteringError("metering_charge_invalid", "priced charge is invalid")
        return charge

    @staticmethod
    def _view(
        receipt: BillingMeteringReceiptRecord,
        usage: UsageEventRecord,
        *,
        replayed: bool = False,
    ) -> MeteredUsage:
        return MeteredUsage(
            receipt_id=receipt.id,
            usage_event_id=usage.id,
            tenant_id=usage.tenant_id,
            space_id=cast(UUID, usage.space_id),
            project_id=cast(UUID, usage.project_id),
            run_id=cast(UUID, usage.run_id),
            runner_id=receipt.runner_id,
            pricing_snapshot_id=usage.pricing_snapshot_id,
            meter=usage.meter,
            quantity=Decimal(usage.quantity),
            unit=usage.unit,
            currency=usage.currency,
            customer_charge_minor=usage.customer_charge_minor,
            occurred_at=_as_utc(usage.occurred_at),
            recorded_at=_as_utc(receipt.recorded_at),
            replayed=replayed,
        )


__all__ = ["BillingMeteringAuthority", "BillingMeteringError", "MeteredUsage"]
