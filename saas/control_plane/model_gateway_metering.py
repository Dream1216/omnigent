"""Canonical customer-meter submissions from immutable true-Run gateway facts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from saas.control_plane.model_gateway_evidence import (
    GatewayRunRequestEvidence,
    decode_gateway_evidence,
    retained_gateway_request,
)
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
)
from saas.control_plane.scheduling_models import CapabilityTokenRecord

GATEWAY_METERS = frozenset({"llm.input_tokens", "llm.output_tokens"})
GATEWAY_EXECUTION_ACTIONS = frozenset({"run.execute", "runtime.interactive.execute"})


def _utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


@dataclass(frozen=True, slots=True)
class GatewayMeteringFact:
    reservation_id: UUID
    tenant_id: UUID
    request: GatewayRunRequestEvidence
    usage: ModelTokenUsage
    occurred_at: datetime
    admitted_at: datetime

    def submissions(self) -> tuple[dict[str, object], ...]:
        return tuple(
            self.submission(meter)
            for meter, quantity in (
                ("llm.input_tokens", self.usage.input_tokens),
                ("llm.output_tokens", self.usage.output_tokens),
            )
            if quantity > 0
        )

    def submission(self, meter: str) -> dict[str, object]:
        if meter not in GATEWAY_METERS:
            raise ValueError("metering_gateway_meter_denied")
        quantity = (
            self.usage.input_tokens if meter == "llm.input_tokens" else self.usage.output_tokens
        )
        if quantity <= 0:
            raise ValueError("metering_gateway_zero_usage")
        suffix = "input" if meter == "llm.input_tokens" else "output"
        return {
            "meter": meter,
            "quantity": str(quantity),
            "unit": "tokens",
            "provider": "deepseek",
            "provider_request_id": f"model-gateway:{self.reservation_id}",
            "idempotency_key": f"model-gateway:{self.reservation_id}:{suffix}",
            "occurred_at": self.occurred_at,
            "attributes": {
                "model": self.request.public_model_id,
                "operation": "responses.create"
                if self.request.wire_api == "openai_responses"
                else "chat.completions.create",
                "request_class": "managed_gateway",
            },
            "model_budget_reservation_id": self.reservation_id,
        }


def read_gateway_metering_fact(
    db: Session,
    *,
    reservation_id: UUID,
    capability: CapabilityTokenRecord,
) -> GatewayMeteringFact:
    budget = db.get(ModelProviderBudgetReservationRecord, reservation_id)
    if (
        budget is None
        or budget.tenant_id != capability.tenant_id
        or budget.run_id != capability.run_id
        or budget.purpose != "tenant_run"
        or budget.status not in {"settled", "released"}
        or budget.outcome_evidence_sha256 is None
        or set(capability.allowed_actions) != GATEWAY_EXECUTION_ACTIONS
    ):
        raise ValueError("metering_gateway_evidence_unavailable")
    rows = {
        row.phase: row
        for row in db.scalars(
            sa.select(ModelGatewayEvidenceRecord).where(
                ModelGatewayEvidenceRecord.reservation_id == reservation_id,
            )
        )
    }
    try:
        original, sent, outcome = rows["request"], rows["in_flight"], rows[budget.status]
        request = retained_gateway_request(original, budget)
        sent_document = decode_gateway_evidence(sent, budget)
        document = decode_gateway_evidence(outcome, budget)
        if not isinstance(request, GatewayRunRequestEvidence):
            raise ValueError
        binding = request.run_binding
        authorized = _utc(sent.created_at)
        occurred = _utc(original.created_at)
        usage = ModelTokenUsage(**document["usage"])
        if (
            document["contract"] != "platform-model-gateway-evidence-v2"
            or sent_document["contract"] != document["contract"]
            or document["request_evidence_sha256"] != original.evidence_sha256
            or sent_document["request_evidence_sha256"] != original.evidence_sha256
            or budget.outcome_evidence_sha256 != outcome.evidence_sha256
            or outcome.budget_version != budget.version
            or document["actual_microusd"] != budget.settled_microusd
            or usage.total_tokens != budget.settled_tokens
            or usage.output_tokens > request.output_token_limit
            or request.model_price.cost(usage, at=occurred) != budget.settled_microusd
            or not _utc(capability.issued_at)
            <= occurred
            <= authorized
            < _utc(capability.expires_at)
            or (capability.revoked_at is not None and _utc(capability.revoked_at) <= authorized)
            or authorized > _utc(outcome.created_at)
            or binding.capability_id != str(capability.id)
            or binding.fence_token != capability.fence_token
            or binding.space_id != str(capability.space_id)
            or binding.project_id != str(capability.project_id)
            or binding.run_id != str(capability.run_id)
            or any(
                capability.resource_scope.get(name) != value
                for name, value in {
                    "tenant_id": str(capability.tenant_id),
                    "space_id": binding.space_id,
                    "project_id": binding.project_id,
                    "run_id": binding.run_id,
                    "runner_id": str(capability.runner_id),
                    "session_id": binding.session_id,
                }.items()
            )
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ValueError("metering_gateway_evidence_unavailable") from None
    return GatewayMeteringFact(
        budget.id, capability.tenant_id, request, usage, occurred, authorized
    )
