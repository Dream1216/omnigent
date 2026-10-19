"""Tenant-scoped publication admission; the browser never receives a live model key."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.db_models import ControlPlaneOutboxEvent, Tenant
from saas.control_plane.model_connections import (
    _IDEMPOTENCY,
    _operation_view,
    authorize_platform_model_operation,
    lock_model_operation_idempotency,
)
from saas.control_plane.model_deployments import (
    CompiledModelDeploymentDraft,
    compile_stored_model_deployment,
)
from saas.control_plane.model_disablement import DISABLEMENT_EVENT, publication_is_disabled
from saas.control_plane.model_pricing import PlatformModelPricingPolicy
from saas.control_plane.model_revocations import ModelSecurityRevocationService
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelPublicationCommandRecord,
    ModelPublicationDisablementRecord,
    ModelPublicationVersionRecord,
    ModelVerificationCommandRecord,
    ModelVerificationReceiptRecord,
)
from saas.control_plane.model_verification_contract import (
    STORED_ATTESTATION_CONTRACT,
    STORED_ATTESTATION_SCOPE,
    ModelVerificationPlan,
    canonical_verification_document,
    compile_model_verification,
    restore_model_verification,
)
from saas.control_plane.platform_models import ModelProviderBudgetReservationRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)

PUBLICATION_EVENT = "platform.model_publication.requested"


def _error(code: str = "platform_model_publication_blocked") -> PlatformSecurityError:
    return PlatformSecurityError(
        code, "Model publication prerequisites are unavailable or changed"
    )


def current_publication_generation(
    db: Session, tenant_id: UUID, draft: CompiledModelDeploymentDraft
) -> int:
    return (
        db.scalar(
            sa.select(sa.func.max(ModelPublicationVersionRecord.generation)).where(
                ModelPublicationVersionRecord.tenant_id == tenant_id,
                ModelPublicationVersionRecord.public_model_id == draft.public_model_id,
                ModelPublicationVersionRecord.wire_api == draft.wire_api,
            )
        )
        or 0
    )


def lock_publication_scope(
    db: Session, tenant_id: UUID, draft: CompiledModelDeploymentDraft
) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            sa.select(
                sa.func.pg_advisory_xact_lock(
                    sa.func.hashtextextended(
                        f"{tenant_id}:{draft.public_model_id}:{draft.wire_api}", 0
                    )
                )
            )
        )


def verified_publication_plan(
    db: Session,
    draft: CompiledModelDeploymentDraft,
    verification_id: UUID,
    pricing: PlatformModelPricingPolicy,
) -> ModelVerificationPlan:
    operation = db.get(ModelProjectionOperationRecord, verification_id)
    command = db.get(ModelVerificationCommandRecord, verification_id)
    receipt = db.get(ModelVerificationReceiptRecord, verification_id)
    generation = db.scalar(
        sa.select(ModelConnectionRecord.credential_generation).where(
            ModelConnectionRecord.id == draft.connection_id,
        )
    )
    credential_generation = db.scalar(
        sa.select(ModelCredentialVersionRecord.generation).where(
            ModelCredentialVersionRecord.id == draft.credential_version_id,
        )
    )
    if (
        operation is None
        or command is None
        or receipt is None
        or operation.action != "verify_deployment"
        or operation.status != "verified"
        or operation.deployment_version_id != draft.deployment_id
        or operation.credential_version_id != draft.credential_version_id
        or command.configuration_sha256 != draft.configuration_sha256
        or receipt.outcome != "passed"
        or receipt.request_attempts != 1
        or receipt.budget_reservation_id is None
        or receipt.actual_microusd is None
        or generation is None
        or generation != credential_generation
    ):
        raise _error()
    try:
        evidence = json.loads(receipt.canonical_evidence)
        witness = evidence["configuration_attestation"]
        if (
            canonical_verification_document(evidence) != receipt.canonical_evidence
            or sha256(receipt.canonical_evidence.encode("ascii")).hexdigest()
            != receipt.evidence_sha256
            or not isinstance(witness, dict)
            or witness.get("contract") != STORED_ATTESTATION_CONTRACT
            or witness.get("scope") != STORED_ATTESTATION_SCOPE
            or witness.get("deployment_id") != str(draft.deployment_id)
            or witness.get("credential_version_id") != str(draft.credential_version_id)
            or witness.get("configuration_sha256") != draft.configuration_sha256
            or re.fullmatch(r"[0-9a-f]{64}", witness.get("stored_state_sha256", "")) is None
        ):
            raise ValueError
        plan = restore_model_verification(
            draft,
            canonical_price=command.canonical_price,
            funding_policy_version=command.funding_policy_version,
        )
        approved = compile_model_verification(
            draft, pricing=pricing, funding_policy_version=command.funding_policy_version
        )
        if plan.price_sha256 != command.price_sha256 or plan.price_sha256 != approved.price_sha256:
            raise ValueError
        budget = db.execute(
            sa.select(
                ModelProviderBudgetReservationRecord.purpose,
                ModelProviderBudgetReservationRecord.test_operation_id,
                ModelProviderBudgetReservationRecord.status,
                ModelProviderBudgetReservationRecord.settled_microusd,
                ModelProviderBudgetReservationRecord.settled_tokens,
                ModelProviderBudgetReservationRecord.outcome_evidence_sha256,
            ).where(ModelProviderBudgetReservationRecord.id == receipt.budget_reservation_id)
        ).one_or_none()
        if budget is None or tuple(budget) != (
            "platform_test",
            verification_id,
            "settled",
            receipt.actual_microusd,
            evidence["usage"]["total_tokens"],
            receipt.evidence_sha256,
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        raise _error() from None
    return plan


def publication_snapshot(
    draft: CompiledModelDeploymentDraft,
    command: ModelPublicationCommandRecord,
    plan: ModelVerificationPlan,
) -> str:
    return canonical_verification_document(
        {
            "schema_version": 1,
            "tenant_id": str(command.tenant_id),
            "public_model_id": draft.public_model_id,
            "display_name": draft.display_name,
            "provider_id": "deepseek",
            "channel_id": "deepseek",
            "transport": "litellm",
            "wire_api": draft.wire_api,
            "deployment_id": str(draft.deployment_id),
            "deployment_alias": draft.alias,
            "connection_id": str(draft.connection_id),
            "credential_version_id": str(draft.credential_version_id),
            "configuration_sha256": draft.configuration_sha256,
            "max_output_tokens": draft.max_output_tokens,
            "generation": command.expected_generation + 1,
            "verification_operation_id": str(command.verification_operation_id),
            "provider_cost": json.loads(plan.canonical_price),
        }
    )


@dataclass(frozen=True, slots=True)
class ModelPublicationView:
    id: UUID
    operation_id: UUID
    tenant_id: UUID
    deployment_version_id: UUID
    public_model_id: str
    display_name: str
    wire_api: str
    generation: int
    configuration_sha256: str
    pricing_revision: str
    created_at: datetime
    provider_id: str = "deepseek"
    channel_id: str = "deepseek"
    transport: str = "litellm"
    runtime_enabled: bool = False
    disabled: bool = False
    disablement_id: UUID | None = None
    disabled_through_generation: int | None = None
    disabled_at: datetime | None = None


def publication_view(
    row: ModelPublicationVersionRecord,
    disablement: ModelPublicationDisablementRecord | None = None,
) -> ModelPublicationView:
    snapshot = json.loads(row.canonical_snapshot)
    if sha256(row.canonical_snapshot.encode("ascii")).hexdigest() != row.snapshot_sha256:
        raise _error()
    return ModelPublicationView(
        row.id,
        row.operation_id,
        row.tenant_id,
        row.deployment_version_id,
        row.public_model_id,
        snapshot["display_name"],
        row.wire_api,
        row.generation,
        row.configuration_sha256,
        snapshot["provider_cost"]["pricing_revision"],
        row.created_at,
        disabled=disablement is not None,
        disablement_id=None if disablement is None else disablement.id,
        disabled_through_generation=None
        if disablement is None
        else disablement.through_generation,
        disabled_at=None
        if disablement is None
        else disablement.created_at.replace(tzinfo=timezone.utc)
        if disablement.created_at.tzinfo is None
        else disablement.created_at.astimezone(timezone.utc),
    )


class ModelPublicationService:
    def __init__(
        self,
        engine: sa.Engine,
        *,
        authorization: PlatformAuthorizationService,
        pricing: PlatformModelPricingPolicy,
    ) -> None:
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_publications", immediate=True
        )
        self._authorization, self._pricing = authorization, pricing
        self.security_revocations = ModelSecurityRevocationService(
            engine, authorization=authorization
        )

    def disable(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        publication_id: UUID,
        expected_generation: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        """Stop unstarted calls through this generation without rewriting history."""
        from saas.control_plane.model_budget import lock_model_provider_budget

        if (
            not isinstance(publication_id, UUID)
            or not publication_id.int
            or type(expected_generation) is not int
            or not 1 <= expected_generation < 2**31
            or not isinstance(idempotency_key, str)
            or _IDEMPOTENCY.fullmatch(idempotency_key) is None
        ):
            raise _error("platform_model_disablement_invalid")
        request_hash = sha256(
            canonical_verification_document(
                {
                    "publication_id": str(publication_id),
                    "expected_generation": expected_generation,
                    "action": "disable_publication",
                }
            ).encode("ascii")
        ).hexdigest()
        now = datetime.now(timezone.utc)
        with self._session("disable_model_publication") as db:
            authorize_platform_model_operation(
                db, self._authorization, actor, "platform.model_provider.publish", now
            )
            lock_model_operation_idempotency(db, actor.principal_id)
            prior = db.scalar(
                sa.select(ModelPublicationDisablementRecord).where(
                    ModelPublicationDisablementRecord.principal_id == actor.principal_id,
                    ModelPublicationDisablementRecord.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                if prior.request_hash != request_hash:
                    raise _error("platform_model_disablement_conflict")
                return self._disablement_view(prior)
            row = db.get(ModelPublicationVersionRecord, publication_id)
            if row is None:
                raise _error("platform_model_publication_not_found")
            stored_draft = db.get(ModelDeploymentVersionRecord, row.deployment_version_id)
            if stored_draft is None:
                raise _error("platform_model_publication_not_found")
            draft = compile_stored_model_deployment(stored_draft)
            # Match the existing single-send fence before changing its model authority.
            lock_model_provider_budget(db)
            lock_publication_scope(db, row.tenant_id, draft)
            if (
                row.generation != expected_generation
                or current_publication_generation(db, row.tenant_id, draft) != expected_generation
                or publication_is_disabled(
                    db,
                    tenant_id=row.tenant_id,
                    public_model_id=row.public_model_id,
                    wire_api=row.wire_api,
                    generation=row.generation,
                )
            ):
                raise _error("platform_model_disablement_conflict")
            recorded_at = (
                db.execute(sa.select(sa.func.clock_timestamp())).scalar_one()
                if db.get_bind().dialect.name == "postgresql"
                else now
            )
            record = ModelPublicationDisablementRecord(
                id=uuid4(),
                tenant_id=row.tenant_id,
                public_model_id=row.public_model_id,
                wire_api=row.wire_api,
                through_generation=row.generation,
                principal_id=actor.principal_id,
                staff_session_id=actor.session_id,
                staff_security_version=actor.security_version,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                created_at=recorded_at,
            )
            db.add(record)
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=None,
                    aggregate_type="platform_model",
                    aggregate_key=str(record.id),
                    event_type=DISABLEMENT_EVENT,
                    idempotency_key="model-disablement:" + str(record.id),
                    request_hash=request_hash,
                    payload={
                        "event_type": DISABLEMENT_EVENT,
                        "schema_version": 1,
                        "disablement_id": str(record.id),
                    },
                )
            )
            return self._disablement_view(record)

    @staticmethod
    def _disablement_view(record: ModelPublicationDisablementRecord) -> dict[str, object]:
        return {
            "disablement_id": record.id,
            "tenant_id": record.tenant_id,
            "public_model_id": record.public_model_id,
            "wire_api": record.wire_api,
            "through_generation": record.through_generation,
            "disabled": True,
            "created_at": record.created_at.replace(tzinfo=timezone.utc)
            if record.created_at.tzinfo is None
            else record.created_at.astimezone(timezone.utc),
            "runtime_enabled": False,
        }

    def admit(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        deployment_id: UUID,
        tenant_id: UUID,
        verification_operation_id: UUID,
        configuration_sha256: str,
        expected_generation: int,
        idempotency_key: str,
    ):
        if (
            any(
                not isinstance(value, UUID) or value.int == 0
                for value in (deployment_id, tenant_id, verification_operation_id)
            )
            or type(expected_generation) is not int
            or not 0 <= expected_generation < 2**31 - 1
            or not isinstance(configuration_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", configuration_sha256) is None
            or not isinstance(idempotency_key, str)
            or _IDEMPOTENCY.fullmatch(idempotency_key) is None
        ):
            raise _error("platform_model_publication_invalid")
        canonical = canonical_verification_document(
            {
                "action": "publish_deployment",
                "deployment_id": str(deployment_id),
                "tenant_id": str(tenant_id),
                "verification_operation_id": str(verification_operation_id),
                "configuration_sha256": configuration_sha256,
                "expected_generation": expected_generation,
            }
        )
        request_hash = sha256(canonical.encode("ascii")).hexdigest()
        at = datetime.now(timezone.utc)
        with self._session("admit_tenant_model_publication") as db:
            authorize_platform_model_operation(
                db, self._authorization, actor, "platform.model_provider.publish", at
            )
            lock_model_operation_idempotency(db, actor.principal_id)
            prior = db.scalar(
                sa.select(ModelProjectionOperationRecord).where(
                    ModelProjectionOperationRecord.actor_principal_id == actor.principal_id,
                    ModelProjectionOperationRecord.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                if prior.action != "publish_deployment" or prior.request_hash != request_hash:
                    raise _error("platform_model_operation_conflict")
                return _operation_view(prior)
            row = db.get(ModelDeploymentVersionRecord, deployment_id)
            tenant_status = db.scalar(sa.select(Tenant.status).where(Tenant.id == tenant_id))
            if row is None or tenant_status not in {"trial", "active"}:
                raise _error()
            draft = compile_stored_model_deployment(row)
            if draft.configuration_sha256 != configuration_sha256:
                raise _error("platform_model_publication_conflict")
            verified_publication_plan(db, draft, verification_operation_id, self._pricing)
            lock_publication_scope(db, tenant_id, draft)
            if current_publication_generation(db, tenant_id, draft) != expected_generation:
                raise _error("platform_model_publication_conflict")
            expires = min(actor.expires_at, actor.authenticated_at + timedelta(minutes=5))
            if expires - at < timedelta(seconds=45):
                raise _error("platform_fresh_auth_required")
            operation = ModelProjectionOperationRecord(
                id=uuid4(),
                connection_id=draft.connection_id,
                credential_version_id=draft.credential_version_id,
                deployment_version_id=draft.deployment_id,
                action="publish_deployment",
                actor_principal_id=actor.principal_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                status="requested",
                version=1,
                created_at=at,
                updated_at=at,
            )
            db.add(operation)
            db.flush()
            db.add(
                ModelPublicationCommandRecord(
                    operation_id=operation.id,
                    tenant_id=tenant_id,
                    verification_operation_id=verification_operation_id,
                    expected_generation=expected_generation,
                    staff_session_id=actor.session_id,
                    staff_security_version=actor.security_version,
                    expires_at=expires,
                    created_at=at,
                )
            )
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=None,
                    aggregate_type="platform_model",
                    aggregate_key=str(operation.id),
                    event_type=PUBLICATION_EVENT,
                    idempotency_key="model-operation:" + str(operation.id),
                    request_hash=request_hash,
                    payload={
                        "event_type": PUBLICATION_EVENT,
                        "schema_version": 1,
                        "operation_id": str(operation.id),
                        "credential_version_id": str(operation.credential_version_id),
                    },
                )
            )
            return _operation_view(operation)

    def find_disablement(self, actor: ValidatedPlatformPrincipal, *, idempotency_key: str):
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise _error("platform_model_disablement_invalid")
        with self._session("find_model_disablement_receipt") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            row = db.scalar(
                sa.select(ModelPublicationDisablementRecord).where(
                    ModelPublicationDisablementRecord.principal_id == actor.principal_id,
                    ModelPublicationDisablementRecord.idempotency_key == idempotency_key,
                )
            )
            return None if row is None else self._disablement_view(row)

    def disablement_receipt(self, actor: ValidatedPlatformPrincipal, disablement_id: UUID):
        with self._session("read_model_disablement_receipt") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            row = db.get(ModelPublicationDisablementRecord, disablement_id)
            if row is None:
                raise _error("platform_model_disablement_not_found")
            return self._disablement_view(row)

    def list(self, actor: ValidatedPlatformPrincipal, *, tenant_id: UUID | None = None):
        with self._session("list_tenant_model_publications") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            latest = (
                sa.select(
                    ModelPublicationVersionRecord.tenant_id,
                    ModelPublicationVersionRecord.public_model_id,
                    ModelPublicationVersionRecord.wire_api,
                    sa.func.max(ModelPublicationVersionRecord.generation).label("generation"),
                )
                .group_by(
                    ModelPublicationVersionRecord.tenant_id,
                    ModelPublicationVersionRecord.public_model_id,
                    ModelPublicationVersionRecord.wire_api,
                )
                .subquery()
            )
            query = (
                sa.select(ModelPublicationVersionRecord, ModelPublicationDisablementRecord)
                .join(
                    latest,
                    sa.and_(
                        *(
                            getattr(ModelPublicationVersionRecord, name) == getattr(latest.c, name)
                            for name in ("tenant_id", "public_model_id", "wire_api", "generation")
                        )
                    ),
                )
                .outerjoin(
                    ModelPublicationDisablementRecord,
                    sa.and_(
                        *(
                            getattr(ModelPublicationDisablementRecord, name)
                            == getattr(ModelPublicationVersionRecord, name)
                            for name in ("tenant_id", "public_model_id", "wire_api")
                        ),
                        ModelPublicationDisablementRecord.through_generation
                        == ModelPublicationVersionRecord.generation,
                    ),
                )
            )
            if tenant_id is not None:
                query = query.where(ModelPublicationVersionRecord.tenant_id == tenant_id)
            return tuple(
                publication_view(row, cutoff)
                for row, cutoff in db.execute(
                    query.order_by(ModelPublicationVersionRecord.created_at.desc()).limit(100)
                )
            )

    def receipt(self, actor: ValidatedPlatformPrincipal, operation_id: UUID):
        with self._session("read_model_publication_receipt") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            operation = db.get(ModelProjectionOperationRecord, operation_id)
            command = db.get(ModelPublicationCommandRecord, operation_id)
            if operation is None or command is None or operation.action != "publish_deployment":
                raise _error("platform_model_publication_not_found")
            row = db.scalar(
                sa.select(ModelPublicationVersionRecord).where(
                    ModelPublicationVersionRecord.operation_id == operation_id,
                )
            )
            return {
                "operation": asdict(_operation_view(operation)),
                "tenant_id": command.tenant_id,
                "expected_generation": command.expected_generation,
                "publication": None
                if row is None
                else asdict(
                    publication_view(
                        row,
                        db.scalar(
                            sa.select(ModelPublicationDisablementRecord)
                            .where(
                                ModelPublicationDisablementRecord.tenant_id == row.tenant_id,
                                ModelPublicationDisablementRecord.public_model_id
                                == row.public_model_id,
                                ModelPublicationDisablementRecord.wire_api == row.wire_api,
                                ModelPublicationDisablementRecord.through_generation
                                >= row.generation,
                            )
                            .order_by(ModelPublicationDisablementRecord.through_generation.desc())
                            .limit(1)
                        ),
                    )
                ),
                "runtime_enabled": False,
            }
