"""Authenticated, customer-safe projection of one Tenant onboarding journey."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Literal
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import TenantMembership
from saas.control_plane.onboarding_models import TenantOnboardingRecord
from saas.control_plane.rls import RlsContext, apply_rls_context

OnboardingCustomerState = Literal[
    "provisioning",
    "ready_for_first_run",
    "complete",
    "recovering",
    "support_required",
]
OnboardingCustomerStage = Literal[
    "billing",
    "runtime",
    "project",
    "activation",
    "first_run",
    "complete",
    "compensation",
    "support",
]

_PUBLIC_STATE_BY_STATUS: dict[str, tuple[OnboardingCustomerState, OnboardingCustomerStage]] = {
    "tenant_created": ("provisioning", "billing"),
    "billing_ready": ("provisioning", "runtime"),
    "runtime_ready": ("provisioning", "project"),
    "project_ready": ("provisioning", "activation"),
    "active": ("ready_for_first_run", "first_run"),
    "completed": ("complete", "complete"),
    "compensating": ("recovering", "compensation"),
    "compensated": ("support_required", "support"),
    "manual_review": ("support_required", "support"),
}
_RESOURCE_VISIBLE_STATUSES = frozenset({"active", "completed"})
_SUPPORT_REFERENCE_STATUSES = frozenset({"compensated", "manual_review"})


class OnboardingStatusError(RuntimeError):
    """Stable status-query failure that reveals no journey existence facts."""

    code = "onboarding_status_unavailable"


@dataclass(frozen=True, slots=True)
class OnboardingStatusView:
    """Allowlisted customer projection; provider and secret fields are absent by design."""

    state: OnboardingCustomerState
    stage: OnboardingCustomerStage
    version: int
    updated_at: datetime
    can_start_first_run: bool
    tenant_id: UUID | None = None
    space_id: UUID | None = None
    default_project_id: UUID | None = None
    trial_ends_at: datetime | None = None
    support_reference: str | None = None


class OnboardingStatusService:
    """Read the latest Saga owned by one server-authenticated Global User."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        bind = session_factory.kw.get("bind")
        if bind is None:
            raise RuntimeError("Onboarding Status Session factory must be bound")
        if bind.dialect.name == "postgresql":
            from saas.onboarding_composition import verify_onboarding_database_authority

            verify_onboarding_database_authority(bind, authority="status")
        self._sessions = session_factory

    def for_actor(self, actor_id: UUID) -> OnboardingStatusView:
        """Return only the customer-safe projection for ``actor_id``."""

        with self._sessions() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id))
            row = db.execute(
                sa.select(
                    TenantOnboardingRecord.id,
                    TenantOnboardingRecord.status,
                    TenantOnboardingRecord.version,
                    TenantOnboardingRecord.last_transition_at,
                    TenantOnboardingRecord.tenant_id,
                    TenantOnboardingRecord.space_id,
                    TenantOnboardingRecord.default_project_id,
                    TenantOnboardingRecord.trial_ends_at,
                )
                .join(
                    TenantMembership,
                    sa.and_(
                        TenantMembership.tenant_id == TenantOnboardingRecord.tenant_id,
                        TenantMembership.user_id == TenantOnboardingRecord.user_id,
                        TenantMembership.status == "active",
                    ),
                )
                .where(TenantOnboardingRecord.user_id == actor_id)
                .order_by(
                    TenantOnboardingRecord.created_at.desc(),
                    TenantOnboardingRecord.id.desc(),
                )
                .limit(1)
            ).one_or_none()
        if row is None:
            raise OnboardingStatusError("Onboarding status is unavailable")
        public = _PUBLIC_STATE_BY_STATUS.get(row.status)
        if public is None:
            raise OnboardingStatusError("Onboarding status is unavailable")
        state, stage = public
        resources_visible = row.status in _RESOURCE_VISIBLE_STATUSES
        support_reference = (
            _support_reference(row.id) if row.status in _SUPPORT_REFERENCE_STATUSES else None
        )
        return OnboardingStatusView(
            state=state,
            stage=stage,
            version=row.version,
            updated_at=row.last_transition_at,
            can_start_first_run=row.status == "active",
            tenant_id=row.tenant_id if resources_visible else None,
            space_id=row.space_id if resources_visible else None,
            default_project_id=row.default_project_id if resources_visible else None,
            trial_ends_at=row.trial_ends_at if resources_visible else None,
            support_reference=support_reference,
        )


def _support_reference(onboarding_id: UUID) -> str:
    digest = sha256(b"omnigent-onboarding-support-v1\0" + onboarding_id.bytes).hexdigest()
    return f"ob-{digest[:32]}"


__all__ = [
    "OnboardingCustomerStage",
    "OnboardingCustomerState",
    "OnboardingStatusError",
    "OnboardingStatusService",
    "OnboardingStatusView",
]
