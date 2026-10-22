"""Single-attempt model tests with durable evidence before financial acknowledgement."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.utils import make_named_managed_session_maker
from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import LiteLLMManagementClient, LiteLLMManagementError
from saas.control_plane.model_budget import (
    ModelProviderBudgetAdmissionService,
    ModelProviderBudgetError,
    ModelProviderBudgetReservationView,
)
from saas.control_plane.model_connections import credential_context
from saas.control_plane.model_deployments import (
    CompiledModelDeploymentDraft,
    compile_stored_model_deployment,
)
from saas.control_plane.model_projection import ModelCredentialProjectionPublisher
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelVerificationBudgetBindingRecord,
    ModelVerificationCommandRecord,
    ModelVerificationReceiptRecord,
)
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.model_verification_contract import (
    ModelVerificationPlan,
    canonical_verification_document,
    restore_model_verification,
)
from saas.control_plane.outbox import OutboxClaimRoute, OutboxPublishError
from saas.control_plane.platform_models import ModelProviderBudgetReservationRecord
from saas.production.litellm_configuration_attestation import (
    LiteLLMAttestationError,
    LiteLLMConfigurationAttestation,
    LiteLLMConfigurationAttestor,
)
from saas.production.model_protocol_probe import (
    ModelProbeAdmission,
    ModelProtocolProbe,
    ModelProtocolProbeError,
    ModelProtocolProbeResult,
)

MODEL_VERIFICATION_ROUTE = OutboxClaimRoute(
    "platform_model",
    "platform.model_verification.requested",
    "platform.model_verification.requested",
)
_KEYS = {"event_type", "operation_id", "credential_version_id", "schema_version"}


def model_verification_enabled(source: Mapping[str, str]) -> bool:
    value = source.get("OMNIGENT_SAAS_MODEL_VERIFICATION_ENABLED", "false")
    if value not in {"true", "false"}:
        raise ValueError("model_verification_flag_invalid")
    return value == "true"


def model_configuration_attestation_enabled(source: Mapping[str, str]) -> bool:
    value = source.get("OMNIGENT_SAAS_MODEL_CONFIG_ATTESTATION_ENABLED", "false")
    if value not in {"true", "false"}:
        raise ValueError("model_configuration_attestation_flag_invalid")
    return value == "true"


class _Stopped(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _Claim:
    operation_id: UUID
    operation_version: int
    event_id: UUID
    actor_id: UUID
    draft: CompiledModelDeploymentDraft
    plan: ModelVerificationPlan
    credential_name: str
    expires_at: datetime
    send: bool
    interrupted: bool = False


@dataclass(slots=True)
class _Invocation:
    attempts: int = 0
    attestation: LiteLLMConfigurationAttestation | None = None
    attestation_completed: bool = False
    started_at: datetime | None = None


def _aware(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


class ModelVerificationPublisher:
    """Projection DB and Billing use distinct injected service identities."""

    def __init__(
        self,
        engine: sa.Engine,
        *,
        management: LiteLLMManagementClient,
        budget: ModelProviderBudgetAdmissionService,
        probe: ModelProtocolProbe,
        attestor: LiteLLMConfigurationAttestor | None = None,
        secret_cipher: SecretCipher | None = None,
    ) -> None:
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_verification_worker", immediate=True
        )
        self._management, self._budget, self._probe = management, budget, probe
        if (attestor is None) != (secret_cipher is None):
            raise ValueError("model_configuration_attestation_incomplete")
        self._attestor, self._cipher = attestor, secret_cipher

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        route = MODEL_VERIFICATION_ROUTE
        if (
            not isinstance(event_id, UUID)
            or event_id.int == 0
            or event_type != route.event_type
            or aggregate_type != route.aggregate_type
            or set(payload) != _KEYS
            or payload.get("event_type") != route.payload_event_type
            or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1
            or payload.get("operation_id") != aggregate_key
        ):
            raise OutboxPublishError(
                "model_verification_event_invalid", retryable=False, pre_side_effect=True
            )
        try:
            operation_id, credential_id = (
                UUID(aggregate_key),
                UUID(str(payload["credential_version_id"])),
            )
        except (ValueError, TypeError, AttributeError):
            raise OutboxPublishError(
                "model_verification_event_invalid", retryable=False, pre_side_effect=True
            ) from None
        claim = self._claim(operation_id, credential_id, event_id)
        if claim is None:
            return
        if not claim.send:
            if claim.interrupted:
                self._retain_interrupted_hold(claim)
            self._resolve_receipt(claim)
            return
        reservation: ModelProviderBudgetReservationView | None = None
        bound = False
        invocation = _Invocation()
        result: ModelProtocolProbeResult | None = None
        outcome, code = "failed", None
        cancelled = False
        try:
            self._assert_live(claim)
            asyncio.run(
                self._management.reconcile_deepseek_deployment(
                    deployment_id=claim.draft.deployment_id,
                    alias=claim.draft.alias,
                    model=claim.draft.public_model_id,
                    credential_name=claim.credential_name,
                )
            )
            self._assert_live(claim)
            invocation.attestation = self._attest(claim)
            self._assert_live(claim)
            now = datetime.now(timezone.utc)
            reservation = self._budget.reserve_platform_test(
                verification_id=claim.operation_id,
                actor_principal_id=claim.actor_id,
                configuration_sha256=claim.draft.configuration_sha256,
                operation_key="model-verification:" + str(claim.operation_id),
                requested_microusd=claim.plan.requested_microusd,
                requested_tokens=claim.plan.requested_tokens,
                expected_policy_version=claim.plan.funding_policy_version,
                ttl=claim.expires_at - now,
                now=now,
            )
            self._bind_budget(claim, reservation)
            bound = True
            if reservation.status == "rejected":
                code = reservation.rejection_code or "model_verification_budget_denied"
            else:
                self._budget.begin_attempt(reservation_id=reservation.id)
                result = asyncio.run(self._invoke(claim, reservation, invocation))
                if not isinstance(result, ModelProtocolProbeResult):
                    raise ValueError("model_verification_result_invalid")
                if invocation.attestation is not None:
                    final_attestation = self._attest(claim)
                    if (
                        final_attestation is None
                        or final_attestation.stored_state_sha256
                        != invocation.attestation.stored_state_sha256
                    ):
                        raise LiteLLMAttestationError("litellm_configuration_changed_during_test")
                    invocation.attestation = final_attestation
                    invocation.attestation_completed = True
                outcome = "passed"
        except _Stopped:
            code = "model_verification_authority_changed"
        except ModelProviderBudgetError as error:
            code = self._safe_code(error.code, "model_verification_budget_failed")
        except LiteLLMAttestationError as error:
            code = self._safe_code(error.code, "litellm_configuration_unattested")
        except LiteLLMManagementError as error:
            code = self._safe_code(error.code, "model_verification_management_failed")
            outcome = "uncertain" if error.uncertain else "failed"
        except ModelProtocolProbeError as error:
            code, outcome = (
                self._safe_code(error.code, "model_verification_protocol_unknown"),
                "uncertain",
            )
        except Exception:  # noqa: BLE001 - never retain provider text or arbitrary exceptions.
            code = "model_verification_outcome_unknown"
            outcome = "uncertain" if invocation.attempts else "failed"
        except asyncio.CancelledError:
            code, outcome, cancelled = "model_verification_cancelled", "uncertain", True
        if reservation is not None and not bound:
            with self._session("reconcile_uncertain_budget_binding_save") as db:
                binding = db.get(ModelVerificationBudgetBindingRecord, claim.operation_id)
                bound = binding is not None and binding.budget_reservation_id == reservation.id
        if reservation is not None and not bound:
            if reservation.status == "reserved":
                self._budget.release(reservation_id=reservation.id)
            reservation = None
        try:
            self._write_receipt(claim, reservation, result, invocation, outcome=outcome, code=code)
        except ValueError:
            if result is None:
                raise
            self._write_receipt(
                claim,
                reservation,
                None,
                invocation,
                outcome="uncertain",
                code="model_verification_result_invalid",
            )
        self._resolve_receipt(claim)
        if cancelled:
            raise asyncio.CancelledError

    @staticmethod
    def _safe_code(value: str, fallback: str) -> str:
        return (
            value
            if isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", value)
            else fallback
        )

    def _claim(self, operation_id: UUID, credential_id: UUID, event_id: UUID) -> _Claim | None:
        with self._session("claim_one_bounded_verification") as db:
            operation = db.scalar(
                sa.select(ModelProjectionOperationRecord)
                .where(ModelProjectionOperationRecord.id == operation_id)
                .with_for_update()
            )
            command = db.get(ModelVerificationCommandRecord, operation_id)
            event = db.execute(
                sa.select(
                    ControlPlaneOutboxEvent.tenant_id,
                    ControlPlaneOutboxEvent.aggregate_type,
                    ControlPlaneOutboxEvent.aggregate_key,
                    ControlPlaneOutboxEvent.event_type,
                    ControlPlaneOutboxEvent.request_hash,
                    ControlPlaneOutboxEvent.payload,
                ).where(ControlPlaneOutboxEvent.id == event_id)
            ).one_or_none()
            route = MODEL_VERIFICATION_ROUTE
            if (
                operation is None
                or command is None
                or operation.action != "verify_deployment"
                or operation.credential_version_id != credential_id
                or event is None
                or tuple(event)
                != (
                    None,
                    route.aggregate_type,
                    str(operation_id),
                    route.event_type,
                    operation.request_hash,
                    {
                        "event_type": route.payload_event_type,
                        "schema_version": 1,
                        "operation_id": str(operation_id),
                        "credential_version_id": str(credential_id),
                    },
                )
            ):
                raise OutboxPublishError(
                    "model_verification_record_invalid", retryable=False, pre_side_effect=True
                )
            row = db.get(ModelDeploymentVersionRecord, operation.deployment_version_id)
            if row is None:
                raise OutboxPublishError(
                    "model_verification_draft_unavailable", retryable=True, pre_side_effect=False
                )
            draft = compile_stored_model_deployment(row)
            plan = restore_model_verification(
                draft,
                canonical_price=command.canonical_price,
                funding_policy_version=command.funding_policy_version,
            )
            if (
                command.configuration_sha256 != draft.configuration_sha256
                or command.price_sha256 != plan.price_sha256
                or command.pricing_revision != plan.pricing_revision
                or command.requested_microusd != plan.requested_microusd
                or command.requested_tokens != plan.requested_tokens
                or command.output_token_limit != plan.output_token_limit
                or operation.request_hash != plan.request_hash
                or row.connection_id != operation.connection_id
                or row.credential_version_id != credential_id
            ):
                raise OutboxPublishError(
                    "model_verification_snapshot_invalid", retryable=True, pre_side_effect=False
                )
            receipt = db.get(ModelVerificationReceiptRecord, operation_id)
            now, expires = datetime.now(timezone.utc), _aware(command.expires_at)
            terminal = operation.status in {"verified", "failed", "uncertain"}
            if terminal and receipt is None:
                return None
            interrupted = operation.status == "applying" and receipt is None
            if interrupted:
                ModelCredentialProjectionPublisher._set_state(
                    db, operation, "uncertain", "model_verification_interrupted", now, event_id
                )
            send = operation.status == "requested" and receipt is None
            credential_name = ""
            if send:
                if expires <= now or not ModelCredentialProjectionPublisher._actor_active(
                    db, operation, now
                ):
                    ModelCredentialProjectionPublisher._set_state(
                        db,
                        operation,
                        "failed",
                        "model_verification_authorization_expired",
                        now,
                        event_id,
                    )
                    return None
                credential = db.get(ModelCredentialVersionRecord, credential_id)
                generation = db.scalar(
                    sa.select(ModelConnectionRecord.credential_generation).where(
                        ModelConnectionRecord.id == operation.connection_id
                    )
                )
                if credential is None or generation != credential.generation:
                    ModelCredentialProjectionPublisher._set_state(
                        db,
                        operation,
                        "failed",
                        "model_verification_credential_changed",
                        now,
                        event_id,
                    )
                    return None
                credential_name = credential.credential_name
                ModelCredentialProjectionPublisher._set_state(
                    db, operation, "applying", None, now, event_id
                )
            return _Claim(
                operation.id,
                operation.version,
                event_id,
                operation.actor_principal_id,
                draft,
                plan,
                credential_name,
                expires,
                send,
                interrupted,
            )

    def _live(self, db: Session, claim: _Claim) -> ModelProjectionOperationRecord:
        operation = db.scalar(
            sa.select(ModelProjectionOperationRecord)
            .where(ModelProjectionOperationRecord.id == claim.operation_id)
            .with_for_update()
        )
        now = datetime.now(timezone.utc)
        if (
            operation is None
            or operation.status != "applying"
            or operation.version != claim.operation_version
            or now >= claim.expires_at
            or not ModelCredentialProjectionPublisher._actor_active(db, operation, now)
        ):
            raise _Stopped
        generation = db.scalar(
            sa.select(ModelConnectionRecord.credential_generation).where(
                ModelConnectionRecord.id == operation.connection_id
            )
        )
        credential_generation = db.scalar(
            sa.select(ModelCredentialVersionRecord.generation).where(
                ModelCredentialVersionRecord.id == operation.credential_version_id
            )
        )
        if generation != credential_generation or generation is None:
            raise _Stopped
        return operation

    def _assert_live(self, claim: _Claim) -> None:
        with self._session("recheck_before_model_effect") as db:
            self._live(db, claim)
            if claim.expires_at - datetime.now(timezone.utc) < timedelta(seconds=90):
                raise _Stopped

    def _attest(self, claim: _Claim) -> LiteLLMConfigurationAttestation | None:
        if self._attestor is None:
            return None
        assert self._cipher is not None
        with self._session("read_canonical_secret_for_bound_storage_check") as db:
            self._live(db, claim)
            credential = db.get(ModelCredentialVersionRecord, claim.draft.credential_version_id)
            if credential is None:
                raise _Stopped
            api_key = self._cipher.decrypt(
                credential.api_key_ciphertext,
                context=credential_context(claim.draft.connection_id, credential.id),
            )
        if not isinstance(api_key, str):
            raise LiteLLMAttestationError("litellm_canonical_credential_unavailable")
        witness = self._attestor.attest(
            draft=claim.draft,
            credential_name=claim.credential_name,
            expected_api_key=api_key,
        )
        if not isinstance(witness, LiteLLMConfigurationAttestation):
            raise LiteLLMAttestationError("litellm_attestation_binding_invalid")
        witness.require_binding(claim.draft)
        return witness

    def _bind_budget(self, claim: _Claim, reservation: ModelProviderBudgetReservationView) -> None:
        if (
            reservation.purpose,
            reservation.test_operation_id,
            reservation.test_configuration_sha256,
            reservation.test_policy_version,
        ) != (
            "platform_test",
            claim.operation_id,
            claim.draft.configuration_sha256,
            claim.plan.funding_policy_version,
        ):
            raise ValueError("model_verification_budget_binding_invalid")
        with self._session("persist_real_test_budget_binding") as db:
            self._live(db, claim)
            stored = db.execute(
                sa.select(
                    ModelProviderBudgetReservationRecord.purpose,
                    ModelProviderBudgetReservationRecord.test_operation_id,
                    ModelProviderBudgetReservationRecord.test_configuration_sha256,
                    ModelProviderBudgetReservationRecord.test_policy_version,
                ).where(ModelProviderBudgetReservationRecord.id == reservation.id)
            ).one_or_none()
            if stored is None or tuple(stored) != (
                "platform_test",
                claim.operation_id,
                claim.draft.configuration_sha256,
                claim.plan.funding_policy_version,
            ):
                raise ValueError("model_verification_budget_binding_invalid")
            db.add(
                ModelVerificationBudgetBindingRecord(
                    operation_id=claim.operation_id,
                    budget_reservation_id=reservation.id,
                    configuration_sha256=claim.draft.configuration_sha256,
                    funding_policy_version=claim.plan.funding_policy_version,
                    admitted_at=datetime.now(timezone.utc),
                )
            )

    async def _invoke(
        self,
        claim: _Claim,
        reservation: ModelProviderBudgetReservationView,
        invocation: _Invocation,
    ) -> ModelProtocolProbeResult:
        self._assert_live(claim)
        key = await self._management.create_inference_key(
            aliases=(claim.draft.alias,),
            key_alias="model-test-" + claim.operation_id.hex,
            duration_seconds=120,
        )
        self._assert_live(claim)
        invocation.started_at, invocation.attempts = datetime.now(timezone.utc), 1
        return await self._probe.run_admitted_probe(
            admission=ModelProbeAdmission(
                claim.operation_id,
                reservation.id,
                claim.draft.deployment_id,
                claim.draft.configuration_sha256,
                min(reservation.expires_at, claim.expires_at),
            ),
            draft=claim.draft,
            inference_key=key,
            now=invocation.started_at,
        )

    def _write_receipt(
        self,
        claim: _Claim,
        reservation: ModelProviderBudgetReservationView | None,
        result: ModelProtocolProbeResult | None,
        invocation: _Invocation,
        *,
        outcome: str,
        code: str | None,
    ) -> None:
        usage, cost, request_hash, latency = (
            None,
            0 if invocation.attempts == 0 else None,
            None,
            None,
        )
        if result is not None:
            if (
                reservation is None
                or invocation.started_at is None
                or (
                    result.verification_id,
                    result.budget_reservation_id,
                    result.deployment_id,
                    result.configuration_sha256,
                    result.wire_api,
                    result.output_token_limit,
                    result.request_attempts,
                )
                != (
                    claim.operation_id,
                    reservation.id,
                    claim.draft.deployment_id,
                    claim.draft.configuration_sha256,
                    claim.draft.wire_api,
                    claim.plan.output_token_limit,
                    1,
                )
            ):
                raise ValueError("model_verification_result_binding_invalid")
            if (
                (
                    result.request_id_sha256 is not None
                    and re.fullmatch(r"[0-9a-f]{64}", result.request_id_sha256) is None
                )
                or type(result.latency_millis) is not int
                or not 0 <= result.latency_millis <= 120_000
            ):
                raise ValueError("model_verification_result_metadata_invalid")
            cost = claim.plan.actual_cost(result.usage, at=invocation.started_at)
            usage, request_hash, latency = (
                asdict(result.usage),
                result.request_id_sha256,
                result.latency_millis,
            )
        now = datetime.now(timezone.utc)
        evidence: dict[str, object] = {
            "schema_version": 1,
            "operation_id": str(claim.operation_id),
            "deployment_id": str(claim.draft.deployment_id),
            "configuration_sha256": claim.draft.configuration_sha256,
            "budget_reservation_id": str(reservation.id) if reservation is not None else None,
            "pricing_revision": claim.plan.pricing_revision,
            "price_sha256": claim.plan.price_sha256,
            "funding_policy_version": claim.plan.funding_policy_version,
            "wire_api": claim.draft.wire_api,
            "outcome": outcome,
            "error_code": code,
            "actual_microusd": cost,
            "usage": usage,
            "request_attempts": invocation.attempts,
            "request_id_sha256": request_hash,
            "attempt_started_at": invocation.started_at.isoformat()
            if invocation.started_at
            else None,
            "latency_millis": latency,
            "occurred_at": now.isoformat(),
            "configuration_readback_scope": "visible_transport_not_masked_credentials",
            "configuration_attestation": invocation.attestation.evidence()
            if invocation.attestation_completed and invocation.attestation is not None
            else None,
        }
        canonical = canonical_verification_document(evidence)
        with self._session("retain_protocol_result_before_settlement") as db:
            db.add(
                ModelVerificationReceiptRecord(
                    operation_id=claim.operation_id,
                    budget_reservation_id=reservation.id if reservation else None,
                    outcome=outcome,
                    actual_microusd=cost,
                    request_attempts=invocation.attempts,
                    error_code=code,
                    canonical_evidence=canonical,
                    evidence_sha256=sha256(canonical.encode("ascii")).hexdigest(),
                    occurred_at=now,
                )
            )

    def _retain_interrupted_hold(self, claim: _Claim) -> None:
        with self._session("read_interrupted_test_budget_binding") as db:
            binding = db.get(ModelVerificationBudgetBindingRecord, claim.operation_id)
            identifier = binding.budget_reservation_id if binding is not None else None
        if identifier is not None:
            try:
                self._budget.mark_uncertain(reservation_id=identifier)
            except ModelProviderBudgetError as error:
                if error.code != "platform_model_budget_reservation_inactive":
                    raise

    def _resolve_receipt(self, claim: _Claim) -> None:
        with self._session("read_retained_verification_receipt") as db:
            receipt = db.get(ModelVerificationReceiptRecord, claim.operation_id)
            if receipt is None:
                return
            canonical, evidence_hash, budget_id = (
                receipt.canonical_evidence,
                receipt.evidence_sha256,
                receipt.budget_reservation_id,
            )
            outcome, code, cost = receipt.outcome, receipt.error_code, receipt.actual_microusd
        if sha256(canonical.encode("ascii")).hexdigest() != evidence_hash:
            raise ValueError("model_verification_evidence_invalid")
        evidence = json.loads(canonical)
        if (
            evidence.get("operation_id") != str(claim.operation_id)
            or evidence.get("configuration_sha256") != claim.draft.configuration_sha256
            or evidence.get("price_sha256") != claim.plan.price_sha256
            or evidence.get("funding_policy_version") != claim.plan.funding_policy_version
            or evidence.get("budget_reservation_id") != (str(budget_id) if budget_id else None)
            or evidence.get("outcome") != outcome
            or evidence.get("error_code") != code
            or evidence.get("actual_microusd") != cost
        ):
            raise ValueError("model_verification_evidence_binding_invalid")
        tokens = 0
        if cost is not None and cost > 0:
            usage = ModelTokenUsage(**evidence["usage"])
            at = datetime.fromisoformat(evidence["attempt_started_at"])
            if claim.plan.actual_cost(usage, at=at) != cost or evidence["request_attempts"] != 1:
                raise ValueError("model_verification_cost_evidence_invalid")
            tokens = usage.total_tokens
        elif cost == 0 and (evidence["request_attempts"] != 0 or evidence["usage"] is not None):
            raise ValueError("model_verification_zero_usage_evidence_invalid")
        if budget_id is not None:
            if cost is None:
                self._retain_interrupted_hold(claim)
            else:
                with self._session("read_bound_test_budget_outcome") as db:
                    budget_status = db.scalar(
                        sa.select(ModelProviderBudgetReservationRecord.status).where(
                            ModelProviderBudgetReservationRecord.id == budget_id
                        )
                    )
                if not (cost == 0 and budget_status in {"rejected", "expired"}):
                    self._budget.resolve_attempt(
                        reservation_id=budget_id,
                        actual_microusd=cost,
                        actual_tokens=tokens,
                        evidence_sha256=evidence_hash,
                    )
        with self._session("acknowledge_verified_protocol_and_finance") as db:
            operation = db.scalar(
                sa.select(ModelProjectionOperationRecord)
                .where(ModelProjectionOperationRecord.id == claim.operation_id)
                .with_for_update()
            )
            if (
                operation is None
                or operation.status != "applying"
                or operation.version != claim.operation_version
            ):
                return
            status = (
                "verified"
                if outcome == "passed"
                else "uncertain"
                if outcome == "uncertain"
                else "failed"
            )
            if status == "verified":
                try:
                    self._live(db, claim)
                except _Stopped:
                    status, code = "failed", "model_verification_authority_changed"
            ModelCredentialProjectionPublisher._set_state(
                db, operation, status, code, datetime.now(timezone.utc), claim.event_id
            )
