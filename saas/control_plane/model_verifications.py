"""Fresh Staff admission of priced model tests through the existing Outbox."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_budget import latest_model_test_funding_policy
from saas.control_plane.model_connections import (
    _IDEMPOTENCY,
    ModelProjectionOperationView,
    _operation_view,
    authorize_platform_model_operation,
    lock_model_operation_idempotency,
)
from saas.control_plane.model_deployments import compile_stored_model_deployment
from saas.control_plane.model_pricing import PlatformModelPricingPolicy
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelVerificationCommandRecord,
    ModelVerificationReceiptRecord,
)
from saas.control_plane.model_verification_contract import compile_model_verification
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)


class ModelVerificationService:
    def __init__(
        self,
        engine: sa.Engine,
        *,
        authorization: PlatformAuthorizationService,
        pricing: PlatformModelPricingPolicy,
    ) -> None:
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_verifications", immediate=True
        )
        self._authorization, self._pricing = authorization, pricing

    def admit(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        deployment_id: UUID,
        configuration_sha256: str,
        expected_funding_policy_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ModelProjectionOperationView:
        at = now or datetime.now(timezone.utc)
        if (
            not isinstance(deployment_id, UUID)
            or deployment_id.int == 0
            or type(expected_funding_policy_version) is not int
            or expected_funding_policy_version < 1
            or not isinstance(configuration_sha256, str)
            or len(configuration_sha256) != 64
            or any(c not in "0123456789abcdef" for c in configuration_sha256)
            or not isinstance(idempotency_key, str)
            or _IDEMPOTENCY.fullmatch(idempotency_key) is None
        ):
            raise PlatformSecurityError(
                "platform_model_verification_invalid", "Model test command is invalid"
            )
        with self._session("admit_priced_verification_command") as db:
            authorize_platform_model_operation(
                db, self._authorization, actor, "platform.model_provider.test", at
            )
            lock_model_operation_idempotency(db, actor.principal_id)
            prior = db.scalar(
                sa.select(ModelProjectionOperationRecord).where(
                    ModelProjectionOperationRecord.actor_principal_id == actor.principal_id,
                    ModelProjectionOperationRecord.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                command = db.get(ModelVerificationCommandRecord, prior.id)
                if (
                    prior.action != "verify_deployment"
                    or prior.deployment_version_id != deployment_id
                    or command is None
                    or command.configuration_sha256 != configuration_sha256
                    or command.funding_policy_version != expected_funding_policy_version
                ):
                    raise PlatformSecurityError(
                        "platform_model_operation_conflict",
                        "Idempotency key was used for another command",
                    )
                return _operation_view(prior)
            row = db.get(ModelDeploymentVersionRecord, deployment_id)
            if row is None:
                raise PlatformSecurityError(
                    "platform_model_deployment_not_found", "Model draft was not found"
                )
            if row.configuration_sha256 != configuration_sha256:
                raise PlatformSecurityError(
                    "platform_model_verification_conflict",
                    "Model configuration fingerprint changed",
                )
            try:
                draft = compile_stored_model_deployment(row)
            except (ValueError, TypeError):
                raise PlatformSecurityError(
                    "platform_model_verification_invalid", "Stored model draft is invalid"
                ) from None
            generation = db.scalar(
                sa.select(ModelConnectionRecord.credential_generation).where(
                    ModelConnectionRecord.id == row.connection_id
                )
            )
            credential_generation = db.scalar(
                sa.select(ModelCredentialVersionRecord.generation).where(
                    ModelCredentialVersionRecord.id == row.credential_version_id
                )
            )
            projected = db.scalar(
                sa.select(ModelProjectionOperationRecord.id)
                .where(
                    ModelProjectionOperationRecord.deployment_version_id == deployment_id,
                    ModelProjectionOperationRecord.action == "create_deployment",
                    ModelProjectionOperationRecord.status == "applied",
                )
                .limit(1)
            )
            if generation != credential_generation or projected is None:
                raise PlatformSecurityError(
                    "platform_model_verification_blocked",
                    "Select a current acknowledged model draft",
                )
            policy = latest_model_test_funding_policy(db)
            if policy is None or not policy.enabled:
                raise PlatformSecurityError(
                    "platform_model_test_funding_unavailable",
                    "Platform-funded model tests are unavailable",
                )
            if policy.version != expected_funding_policy_version:
                raise PlatformSecurityError(
                    "platform_model_test_funding_conflict", "Model test funding changed"
                )
            try:
                plan = compile_model_verification(
                    draft, pricing=self._pricing, funding_policy_version=policy.version
                )
            except ValueError:
                raise PlatformSecurityError(
                    "platform_model_verification_pricing_unavailable",
                    "Approved model cost rates are unavailable",
                ) from None
            if (
                plan.requested_microusd > policy.max_test_microusd
                or plan.requested_tokens > policy.max_test_tokens
            ):
                raise PlatformSecurityError(
                    "platform_model_verification_blocked",
                    "Model test exceeds the configured per-call funding limit",
                )
            expires_at = min(
                actor.expires_at,
                actor.authenticated_at + timedelta(minutes=5),
                at + timedelta(minutes=5),
            )
            if expires_at - at < timedelta(seconds=120):
                raise PlatformSecurityError(
                    "platform_fresh_auth_required",
                    "Renew Staff authentication before starting a model test",
                )
            operation = ModelProjectionOperationRecord(
                id=uuid4(),
                connection_id=row.connection_id,
                credential_version_id=row.credential_version_id,
                deployment_version_id=row.id,
                action="verify_deployment",
                actor_principal_id=actor.principal_id,
                idempotency_key=idempotency_key,
                request_hash=plan.request_hash,
                status="requested",
                version=1,
                created_at=at,
                updated_at=at,
            )
            db.add(operation)
            db.flush()
            db.add(
                ModelVerificationCommandRecord(
                    operation_id=operation.id,
                    provider_id="deepseek",
                    configuration_sha256=configuration_sha256,
                    expires_at=expires_at,
                    **{key: value for key, value in asdict(plan).items() if key != "request_hash"},
                )
            )
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=None,
                    aggregate_type="platform_model",
                    aggregate_key=str(operation.id),
                    event_type="platform.model_verification.requested",
                    idempotency_key="model-operation:" + str(operation.id),
                    request_hash=operation.request_hash,
                    payload={
                        "event_type": "platform.model_verification.requested",
                        "operation_id": str(operation.id),
                        "credential_version_id": str(operation.credential_version_id),
                        "schema_version": 1,
                    },
                )
            )
            return _operation_view(operation)

    def receipt(self, actor: ValidatedPlatformPrincipal, operation_id: UUID) -> dict[str, object]:
        with self._session("read_verification_evidence") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            operation = db.get(ModelProjectionOperationRecord, operation_id)
            command = db.get(ModelVerificationCommandRecord, operation_id)
            if operation is None or operation.action != "verify_deployment" or command is None:
                raise PlatformSecurityError(
                    "platform_model_verification_not_found", "Model test was not found"
                )
            receipt = db.get(ModelVerificationReceiptRecord, operation_id)
            return {
                "operation": asdict(_operation_view(operation)),
                "configuration_sha256": command.configuration_sha256,
                "pricing_revision": command.pricing_revision,
                "funding_policy_version": command.funding_policy_version,
                "requested_microusd": command.requested_microusd,
                "requested_tokens": command.requested_tokens,
                "output_token_limit": command.output_token_limit,
                "expires_at": command.expires_at,
                "evidence": json.loads(receipt.canonical_evidence)
                if receipt is not None
                else None,
                "runtime_enabled": False,
            }
