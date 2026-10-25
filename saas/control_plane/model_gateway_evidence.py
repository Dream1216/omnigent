"""Non-secret request and usage facts, retained in the existing budget transaction."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_pricing import PlatformModelPrice
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
)

GATEWAY_EVIDENCE_EVENT = "model_gateway.evidence_retained"
GATEWAY_EVIDENCE_AGGREGATE = "model_gateway_budget"
_CONTRACT = "platform-model-gateway-evidence-v1"
_RUN_CONTRACT = "platform-model-gateway-evidence-v2"


@dataclass(frozen=True, slots=True)
class GatewayRequestEvidence:
    public_model_id: str
    wire_api: str
    pricing_revision: str
    model_price: PlatformModelPrice
    output_token_limit: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.public_model_id, str)
            or not 1 <= len(self.public_model_id) <= 128
            or any(not 33 <= ord(char) <= 126 for char in self.public_model_id)
            or not isinstance(self.wire_api, str)
            or self.wire_api not in {"openai_chat_completions", "openai_responses"}
            or not isinstance(self.pricing_revision, str)
            or not 1 <= len(self.pricing_revision) <= 32
            or any(not 33 <= ord(char) <= 126 for char in self.pricing_revision)
            or not isinstance(self.model_price, PlatformModelPrice)
            or self.model_price.model_sha256 != sha256(self.public_model_id.encode()).hexdigest()
            or type(self.output_token_limit) is not int
            or not 1 <= self.output_token_limit <= 65536
        ):
            raise ValueError("platform_model_gateway_request_evidence_invalid")


@dataclass(frozen=True, slots=True)
class GatewayRunBinding:
    run_id: str
    session_id: str
    space_id: str
    project_id: str
    actor_id: str
    capability_id: str
    model_token_id: str
    customer_pricing_snapshot_id: str
    fence_token: int
    publication_generation: int
    publication_snapshot_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "run_id",
            "session_id",
            "space_id",
            "project_id",
            "actor_id",
            "capability_id",
            "model_token_id",
            "customer_pricing_snapshot_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or str(UUID(value)) != value or UUID(value).int == 0:
                raise ValueError("platform_model_gateway_run_binding_invalid")
        if (
            type(self.fence_token) is not int
            or not 1 <= self.fence_token < 2**63
            or type(self.publication_generation) is not int
            or not 1 <= self.publication_generation < 2**31
            or not isinstance(self.publication_snapshot_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.publication_snapshot_sha256) is None
        ):
            raise ValueError("platform_model_gateway_run_binding_invalid")


@dataclass(frozen=True, slots=True)
class GatewayRunRequestEvidence(GatewayRequestEvidence):
    run_binding: GatewayRunBinding

    def __post_init__(self) -> None:
        GatewayRequestEvidence.__post_init__(self)
        if not isinstance(self.run_binding, GatewayRunBinding):
            raise ValueError("platform_model_gateway_run_binding_invalid")


def gateway_request_material(request: GatewayRequestEvidence) -> dict:
    return asdict(request)


@dataclass(frozen=True, slots=True)
class GatewayEvidenceView:
    id: UUID
    reservation_id: UUID
    phase: str
    canonical_evidence: str
    evidence_sha256: str


def canonical_gateway_evidence(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def gateway_request_record(db: Session, reservation_id: UUID) -> ModelGatewayEvidenceRecord | None:
    return db.scalar(
        sa.select(ModelGatewayEvidenceRecord).where(
            ModelGatewayEvidenceRecord.reservation_id == reservation_id,
            ModelGatewayEvidenceRecord.phase == "request",
        )
    )


def gateway_admission(budget: ModelProviderBudgetReservationRecord) -> dict[str, int]:
    return {
        name: getattr(budget, name)
        for name in (
            "requested_microusd",
            "requested_tokens",
            "admitted_microusd",
            "admitted_tokens",
        )
    }


def decode_gateway_evidence(
    row: ModelGatewayEvidenceRecord, budget: ModelProviderBudgetReservationRecord
) -> dict:
    if sha256(row.canonical_evidence.encode("ascii")).hexdigest() != row.evidence_sha256:
        raise ValueError("platform_model_gateway_evidence_drift")
    value = json.loads(row.canonical_evidence)
    contract = value.get("contract") if isinstance(value, dict) else None
    identity = "run_id" if contract == _RUN_CONTRACT else "session_id"
    expected = {
        "reservation_id": str(budget.id),
        "tenant_id": str(budget.tenant_id),
        identity: str(budget.run_id),
        "provider_id": budget.provider_id,
        "configuration_version": budget.configuration_version,
        "phase": row.phase,
        "budget_version": row.budget_version,
        "admission": gateway_admission(budget),
        "contract": contract,
    }
    if (
        not isinstance(value, dict)
        or contract not in {_CONTRACT, _RUN_CONTRACT}
        or ("session_id" if identity == "run_id" else "run_id") in value
        or canonical_gateway_evidence(value) != row.canonical_evidence
        or any(value.get(name) != expected_value for name, expected_value in expected.items())
    ):
        raise ValueError("platform_model_gateway_evidence_drift")
    return value


def retained_gateway_request(
    row: ModelGatewayEvidenceRecord, budget: ModelProviderBudgetReservationRecord
) -> GatewayRequestEvidence:
    document = decode_gateway_evidence(row, budget)
    value = document["request"]
    managed = document["contract"] == _RUN_CONTRACT
    request_class = GatewayRunRequestEvidence if managed else GatewayRequestEvidence
    if not isinstance(value, dict) or set(value) != set(request_class.__dataclass_fields__):
        raise ValueError("platform_model_gateway_evidence_drift")
    values = (
        value["public_model_id"],
        value["wire_api"],
        value["pricing_revision"],
        PlatformModelPrice(**value["model_price"]),
        value["output_token_limit"],
    )
    if managed:
        binding = GatewayRunBinding(**value["run_binding"])
        if binding.run_id != str(budget.run_id):
            raise ValueError("platform_model_gateway_evidence_drift")
        return GatewayRunRequestEvidence(*values, binding)
    return GatewayRequestEvidence(*values)


def retain_gateway_evidence(
    db: Session,
    budget: ModelProviderBudgetReservationRecord,
    *,
    at: datetime,
    request: GatewayRequestEvidence | None = None,
    usage: ModelTokenUsage | None = None,
    reason: str | None = None,
) -> ModelGatewayEvidenceRecord | None:
    first = gateway_request_record(db, budget.id) if request is None else None
    if request is None and first is None:
        return None
    if budget.purpose != "tenant_run" or budget.tenant_id is None or budget.run_id is None:
        raise ValueError("platform_model_gateway_evidence_scope_invalid")
    phase = "request" if request is not None else budget.status
    if request is not None:
        contract = _RUN_CONTRACT if isinstance(request, GatewayRunRequestEvidence) else _CONTRACT
    else:
        assert first is not None
        contract = decode_gateway_evidence(first, budget)["contract"]
    material = {
        "contract": contract,
        "phase": phase,
        "reservation_id": str(budget.id),
        "tenant_id": str(budget.tenant_id),
        "run_id" if contract == _RUN_CONTRACT else "session_id": str(budget.run_id),
        "provider_id": budget.provider_id,
        "configuration_version": budget.configuration_version,
        "budget_version": budget.version,
        "status": budget.status,
        "admission": gateway_admission(budget),
        "request": gateway_request_material(request) if request is not None else None,
        "request_evidence_sha256": first.evidence_sha256 if first is not None else None,
        "usage": asdict(usage) if usage is not None else None,
        "actual_microusd": budget.settled_microusd if usage is not None else None,
        "reason": reason,
        "occurred_at": at.astimezone(timezone.utc).isoformat(),
    }
    canonical = canonical_gateway_evidence(material)
    witness = sha256(canonical.encode("ascii")).hexdigest()
    row = ModelGatewayEvidenceRecord(
        id=uuid4(),
        tenant_id=budget.tenant_id,
        reservation_id=budget.id,
        phase=phase,
        budget_version=budget.version,
        canonical_evidence=canonical,
        evidence_sha256=witness,
        created_at=at,
    )
    if usage is not None:
        budget.outcome_evidence_sha256 = witness
        # The receipt guard must observe this outcome binding before INSERT.
        db.flush([budget])
    db.add(row)
    # The reference-only Outbox INSERT policy must see the retained evidence.
    db.flush()
    db.add(
        ControlPlaneOutboxEvent(
            id=uuid4(),
            tenant_id=budget.tenant_id,
            aggregate_type=GATEWAY_EVIDENCE_AGGREGATE,
            aggregate_key=str(budget.id),
            event_type=GATEWAY_EVIDENCE_EVENT,
            payload={
                "event_type": GATEWAY_EVIDENCE_EVENT,
                "tenant_id": str(budget.tenant_id),
                "reservation_id": str(budget.id),
                "evidence_id": str(row.id),
                "evidence_sha256": witness,
            },
            idempotency_key="model-gateway-evidence:" + row.id.hex,
            request_hash=witness,
            attempt_count=0,
            created_at=at,
        )
    )
    return row
