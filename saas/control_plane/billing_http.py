"""Content-blind Tenant Billing administration API for the shared SaaS console."""

from __future__ import annotations

from datetime import datetime
from types import MappingProxyType
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from saas.control_plane.billing import (
    BalanceView,
    BillingControlPlane,
    BillingControlPlaneError,
    BillingPeriodCloseView,
    EntitlementView,
    ReconciliationView,
    SubscriptionView,
    UsageEventView,
)
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.permissions import PERMISSION_CATALOG

BILLING_ADMIN_ROUTE_PERMISSIONS = MappingProxyType(
    {
        "GET /tenants/{tenant}/billing": "billing.read",
        "PUT /tenants/{tenant}/billing/subscription": "billing.manage",
        "POST /tenants/{tenant}/billing/pricing-snapshots": "billing.manage",
        "PUT /tenants/{tenant}/billing/entitlements": "billing.manage",
        "GET /tenants/{tenant}/billing/usage-events": "billing.read",
        "GET /tenants/{tenant}/billing/ledger": "billing.read",
        "GET /tenants/{tenant}/billing/reconciliations": "billing.read",
        "POST /tenants/{tenant}/billing/reconciliations": "billing.manage",
        "GET /tenants/{tenant}/billing/period-closes": "billing.read",
        "POST /tenants/{tenant}/billing/period-closes": "billing.manage",
        "GET /tenants/{tenant}/billing/reconciliations/{batch}/mismatches": "billing.read",
        "POST /tenants/{tenant}/billing/reconciliation-mismatches/{mismatch}/resolve": (
            "billing.manage"
        ),
    }
)


class SubscriptionBody(BaseModel):
    plan_key: str = Field(min_length=1, max_length=128)
    status: Literal["trialing", "active", "past_due", "suspended", "canceled"]
    current_period_start: datetime
    current_period_end: datetime
    trial_ends_at: datetime | None = None
    cancel_at_period_end: bool = False
    provider: str | None = Field(default=None, min_length=1, max_length=64)
    provider_customer_ref: str | None = Field(default=None, min_length=1, max_length=256)
    provider_subscription_ref: str | None = Field(default=None, min_length=1, max_length=256)
    provider_event_cursor: str | None = Field(default=None, min_length=1, max_length=256)
    expected_version: int | None = Field(default=None, ge=1)


class PricingRateBody(BaseModel):
    unit: str = Field(min_length=1, max_length=64)
    unit_size: str = Field(min_length=1, max_length=64)
    minor_per_unit: int = Field(gt=0, le=10**12)


class PricingSnapshotBody(BaseModel):
    plan_key: str = Field(min_length=1, max_length=128)
    currency: str = Field(min_length=3, max_length=3)
    rates: dict[str, PricingRateBody] = Field(min_length=1, max_length=128)
    effective_from: datetime
    effective_until: datetime | None = None


class EntitlementBody(BaseModel):
    scope_type: Literal["tenant", "space", "project", "user", "model"]
    space_id: UUID | None = None
    project_id: UUID | None = None
    user_id: UUID | None = None
    model_key: str | None = Field(default=None, min_length=1, max_length=256)
    meter: str = Field(min_length=1, max_length=128)
    unit: str = Field(min_length=1, max_length=64)
    limit_quantity: str | None = Field(default=None, min_length=1, max_length=64)
    concurrency_limit: int | None = Field(default=None, ge=1, le=1_000_000)
    hard_limit: bool = True
    period: Literal["none", "day", "month"] = "month"
    period_start: datetime
    period_end: datetime | None = None
    status: Literal["active", "suspended", "expired"] = "active"
    expected_version: int | None = Field(default=None, ge=1)


class ReconciliationBody(BaseModel):
    period_start: datetime
    period_end: datetime


class MismatchResolutionBody(BaseModel):
    resolution: str = Field(min_length=1, max_length=1024)


def create_billing_admin_router(
    *, auth_provider: SaasAuthProvider, billing: BillingControlPlane
) -> APIRouter:
    """Create billing routes without exposing metering ingestion or credit issuance."""

    router = APIRouter()

    @router.get("/tenants/{tenant_id}/billing")
    def get_overview(tenant_id: UUID, request: Request, response: Response) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            overview = billing.get_overview(
                actor_id=principal.session.user_id, tenant_id=tenant_id
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        subscription = overview["subscription"]
        balance = overview["balance"]
        entitlements = overview["entitlements"]
        reconciliation = overview["latest_reconciliation"]
        return {
            "subscription": _subscription_payload(subscription)
            if isinstance(subscription, SubscriptionView)
            else None,
            "balance": _balance_payload(balance) if isinstance(balance, BalanceView) else None,
            "entitlements": [
                _entitlement_payload(value)
                for value in entitlements
                if isinstance(value, EntitlementView)
            ]
            if isinstance(entitlements, tuple)
            else [],
            "latest_reconciliation": _reconciliation_payload(reconciliation)
            if isinstance(reconciliation, ReconciliationView)
            else None,
        }

    @router.put("/tenants/{tenant_id}/billing/subscription")
    def configure_subscription(
        tenant_id: UUID,
        body: SubscriptionBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            result = billing.configure_subscription(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                plan_key=body.plan_key,
                status=body.status,
                current_period_start=body.current_period_start,
                current_period_end=body.current_period_end,
                trial_ends_at=body.trial_ends_at,
                cancel_at_period_end=body.cancel_at_period_end,
                provider=body.provider,
                provider_customer_ref=body.provider_customer_ref,
                provider_subscription_ref=body.provider_subscription_ref,
                provider_event_cursor=body.provider_event_cursor,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        return _subscription_payload(result)

    @router.post("/tenants/{tenant_id}/billing/pricing-snapshots", status_code=201)
    def create_pricing_snapshot(
        tenant_id: UUID,
        body: PricingSnapshotBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            result = billing.create_pricing_snapshot(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                plan_key=body.plan_key,
                currency=body.currency,
                rates={key: value.model_dump() for key, value in body.rates.items()},
                effective_from=body.effective_from,
                effective_until=body.effective_until,
                idempotency_key=idempotency_key,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        return {
            "pricing_snapshot_id": str(result.id),
            "plan_key": result.plan_key,
            "currency": result.currency,
            "version": result.version,
            "effective_from": result.effective_from.isoformat(),
            "effective_until": result.effective_until.isoformat()
            if result.effective_until
            else None,
            "replayed": result.replayed,
        }

    @router.put("/tenants/{tenant_id}/billing/entitlements")
    def set_entitlement(
        tenant_id: UUID,
        body: EntitlementBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            result = billing.set_entitlement(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                scope_type=body.scope_type,
                space_id=body.space_id,
                project_id=body.project_id,
                user_id=body.user_id,
                model_key=body.model_key,
                meter=body.meter,
                unit=body.unit,
                limit_quantity=body.limit_quantity,
                concurrency_limit=body.concurrency_limit,
                hard_limit=body.hard_limit,
                period=body.period,
                period_start=body.period_start,
                period_end=body.period_end,
                status=body.status,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        return _entitlement_payload(result)

    @router.get("/tenants/{tenant_id}/billing/usage-events")
    def list_usage(
        tenant_id: UUID,
        request: Request,
        response: Response,
        period_start: datetime,
        period_end: datetime,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = billing.list_usage(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                period_start=period_start,
                period_end=period_end,
                limit=limit,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {"items": [_usage_payload(value) for value in values]}

    @router.get("/tenants/{tenant_id}/billing/ledger")
    def list_ledger(
        tenant_id: UUID,
        request: Request,
        response: Response,
        period_start: datetime,
        period_end: datetime,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = billing.list_ledger(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                period_start=period_start,
                period_end=period_end,
                limit=limit,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [
                {
                    **value,
                    "occurred_at": value["occurred_at"].isoformat()
                    if isinstance(value["occurred_at"], datetime)
                    else value["occurred_at"],
                }
                for value in values
            ]
        }

    @router.get("/tenants/{tenant_id}/billing/reconciliations")
    def list_reconciliations(
        tenant_id: UUID,
        request: Request,
        response: Response,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = billing.list_reconciliations(
                actor_id=principal.session.user_id, tenant_id=tenant_id, limit=limit
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {"items": [_reconciliation_payload(value) for value in values]}

    @router.post("/tenants/{tenant_id}/billing/reconciliations", status_code=201)
    def reconcile(
        tenant_id: UUID,
        body: ReconciliationBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            result = billing.reconcile(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                period_start=body.period_start,
                period_end=body.period_end,
                idempotency_key=idempotency_key,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        return _reconciliation_payload(result)

    @router.get("/tenants/{tenant_id}/billing/period-closes")
    def list_period_closes(
        tenant_id: UUID,
        request: Request,
        response: Response,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = billing.list_period_closes(
                actor_id=principal.session.user_id, tenant_id=tenant_id, limit=limit
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {"items": [_period_close_payload(value) for value in values]}

    @router.post("/tenants/{tenant_id}/billing/period-closes", status_code=201)
    def close_period(
        tenant_id: UUID,
        body: ReconciliationBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            result = billing.close_period(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                period_start=body.period_start,
                period_end=body.period_end,
                idempotency_key=idempotency_key,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        return _period_close_payload(result)

    @router.get("/tenants/{tenant_id}/billing/reconciliations/{batch_id}/mismatches")
    def list_mismatches(
        tenant_id: UUID,
        batch_id: UUID,
        request: Request,
        response: Response,
        status: Literal["open", "resolved"] | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            values = billing.list_reconciliation_mismatches(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                status=status,
                limit=limit,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [
                {
                    **value,
                    "resolved_at": value["resolved_at"].isoformat()
                    if isinstance(value["resolved_at"], datetime)
                    else value["resolved_at"],
                }
                for value in values
            ]
        }

    @router.post("/tenants/{tenant_id}/billing/reconciliation-mismatches/{mismatch_id}/resolve")
    def resolve_mismatch(
        tenant_id: UUID,
        mismatch_id: UUID,
        body: MismatchResolutionBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _principal(auth_provider, request)
        try:
            result = billing.resolve_mismatch(
                actor_id=principal.session.user_id,
                tenant_id=tenant_id,
                mismatch_id=mismatch_id,
                resolution=body.resolution,
                idempotency_key=idempotency_key,
            )
        except BillingControlPlaneError as error:
            raise _http_error(error) from error
        return {"mismatch_id": str(result), "status": "resolved"}

    return router


def _principal(auth_provider: SaasAuthProvider, request: Request):
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "authentication_required", "message": "login required"},
        )
    return principal


def _http_error(error: BillingControlPlaneError) -> HTTPException:
    if error.code == "billing_forbidden":
        status = 403
    elif error.code.endswith("_not_found") or error.code in {
        "subscription_missing",
        "usage_not_found",
    }:
        status = 404
    elif error.code.endswith("_invalid"):
        status = 422
    else:
        status = 409
    return HTTPException(
        status_code=status,
        detail={"code": error.code, "message": str(error)},
    )


def _subscription_payload(value: SubscriptionView) -> dict[str, object]:
    return {
        "subscription_id": str(value.id),
        "plan_key": value.plan_key,
        "status": value.status,
        "provider": value.provider,
        "provider_customer_ref": value.provider_customer_ref,
        "provider_subscription_ref": value.provider_subscription_ref,
        "current_period_start": value.current_period_start.isoformat(),
        "current_period_end": value.current_period_end.isoformat(),
        "trial_ends_at": value.trial_ends_at.isoformat() if value.trial_ends_at else None,
        "cancel_at_period_end": value.cancel_at_period_end,
        "version": value.version,
        "replayed": value.replayed,
    }


def _balance_payload(value: BalanceView) -> dict[str, object]:
    return {
        "currency": value.currency,
        "available_minor": value.available_minor,
        "reserved_minor": value.reserved_minor,
        "consumed_minor": value.consumed_minor,
        "version": value.version,
    }


def _entitlement_payload(value: EntitlementView) -> dict[str, object]:
    return {
        "entitlement_id": str(value.id),
        "subscription_id": str(value.subscription_id),
        "scope_type": value.scope_type,
        "scope_key": value.scope_key,
        "meter": value.meter,
        "unit": value.unit,
        "limit_quantity": str(value.limit_quantity) if value.limit_quantity is not None else None,
        "reserved_quantity": str(value.reserved_quantity),
        "consumed_quantity": str(value.consumed_quantity),
        "concurrency_limit": value.concurrency_limit,
        "active_reservations": value.active_reservations,
        "hard_limit": value.hard_limit,
        "period": value.period,
        "period_start": value.period_start.isoformat(),
        "period_end": value.period_end.isoformat() if value.period_end else None,
        "status": value.status,
        "version": value.version,
        "replayed": value.replayed,
    }


def _usage_payload(value: UsageEventView) -> dict[str, object]:
    return {
        "usage_event_id": str(value.id),
        "meter": value.meter,
        "quantity": str(value.quantity),
        "unit": value.unit,
        "provider": value.provider,
        "provider_request_id": value.provider_request_id,
        "pricing_snapshot_id": str(value.pricing_snapshot_id),
        "currency": value.currency,
        "customer_charge_minor": value.customer_charge_minor,
        "occurred_at": value.occurred_at.isoformat(),
    }


def _reconciliation_payload(value: ReconciliationView) -> dict[str, object]:
    return {
        "batch_id": str(value.id),
        "period_start": value.period_start.isoformat(),
        "period_end": value.period_end.isoformat(),
        "status": value.status,
        "usage_event_count": value.usage_event_count,
        "customer_settlement_count": value.customer_settlement_count,
        "provider_cost_count": value.provider_cost_count,
        "customer_charge_minor": value.customer_charge_minor,
        "customer_settled_minor": value.customer_settled_minor,
        "provider_cost_minor": value.provider_cost_minor,
        "mismatch_count": value.mismatch_count,
        "evidence_sha256": value.evidence_sha256,
        "replayed": value.replayed,
    }


def _period_close_payload(value: BillingPeriodCloseView) -> dict[str, object]:
    return {
        "period_close_id": str(value.id),
        "reconciliation_batch_id": str(value.reconciliation_batch_id),
        "period_start": value.period_start.isoformat(),
        "period_end": value.period_end.isoformat(),
        "status": value.status,
        "rolled_entitlement_count": value.rolled_entitlement_count,
        "usage_event_count": value.usage_event_count,
        "customer_charge_minor": value.customer_charge_minor,
        "customer_settled_minor": value.customer_settled_minor,
        "provider_cost_minor": value.provider_cost_minor,
        "reconciliation_evidence_sha256": value.reconciliation_evidence_sha256,
        "close_evidence_sha256": value.close_evidence_sha256,
        "closed_by": str(value.closed_by),
        "closed_at": value.closed_at.isoformat(),
        "replayed": value.replayed,
    }


def validate_billing_admin_route_permissions() -> None:
    """Fail CI when the Billing Admin surface drifts from the permission catalog."""

    unknown = set(BILLING_ADMIN_ROUTE_PERMISSIONS.values()) - set(PERMISSION_CATALOG)
    if unknown:
        raise RuntimeError(f"Billing Admin routes reference unknown permissions: {unknown}")


validate_billing_admin_route_permissions()
