"""Single-attempt credential projection through the existing durable Outbox."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.utils import make_named_managed_session_maker
from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import LiteLLMManagementClient, LiteLLMManagementError
from saas.control_plane.model_connections import credential_context
from saas.control_plane.model_routing_models import (
    ModelCredentialVersionRecord,
    ModelProjectionOperationRecord,
    ModelProjectionTransitionRecord,
)
from saas.control_plane.outbox import OutboxClaimRoute, OutboxPublishError
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)

MODEL_CREDENTIAL_PROJECTION_ROUTE = OutboxClaimRoute(
    aggregate_type="platform_model",
    event_type="platform.model_projection.requested",
    payload_event_type="platform.model_projection.requested",
)
_PAYLOAD_KEYS = {"event_type", "operation_id", "credential_version_id", "schema_version"}
_MANAGEMENT_ERROR_CODES = {
    "litellm_management_denied",
    "litellm_management_conflict",
    "litellm_management_rejected",
    "litellm_management_unreachable",
    "litellm_contract_invalid",
}


@dataclass(frozen=True, slots=True)
class _ProjectionClaim:
    operation_id: UUID
    operation_version: int
    event_id: UUID
    credential_name: str
    api_key: str = field(repr=False)


class ModelCredentialProjectionPublisher:
    """Requires a dedicated projection authority, never a browser DB identity."""

    def __init__(
        self,
        engine: sa.Engine,
        *,
        secret_cipher: SecretCipher,
        management: LiteLLMManagementClient,
    ) -> None:
        self._sessions = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_projection", immediate=True
        )
        self._cipher, self._management = secret_cipher, management

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        route = MODEL_CREDENTIAL_PROJECTION_ROUTE
        if (
            event_id.int == 0
            or event_type != route.event_type
            or aggregate_type != route.aggregate_type
            or set(payload) != _PAYLOAD_KEYS
            or payload.get("event_type") != route.payload_event_type
            or type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != 1
            or payload.get("operation_id") != aggregate_key
            or not isinstance(payload.get("credential_version_id"), str)
        ):
            raise self._invalid_event()
        try:
            operation_id = UUID(aggregate_key)
            credential_id = UUID(str(payload["credential_version_id"]))
        except (ValueError, AttributeError):
            raise self._invalid_event() from None
        claim = self._claim(operation_id, credential_id, event_id)
        if claim is None:
            return
        try:
            asyncio.run(
                self._management.create_deepseek_credential(
                    name=claim.credential_name,
                    api_key=claim.api_key,
                )
            )
        except LiteLLMManagementError as error:
            uncertain = (
                error.uncertain
                or error.status_code == 409
                or error.code not in _MANAGEMENT_ERROR_CODES
            )
            code = (
                error.code
                if error.code in _MANAGEMENT_ERROR_CODES
                else "litellm_projection_outcome_unknown"
            )
            self._finish(
                claim,
                status="uncertain" if uncertain else "failed",
                error_code="litellm_projection_conflict_unverified"
                if error.status_code == 409
                else code,
            )
        except Exception:  # noqa: BLE001 - no provider exception content enters evidence.
            self._finish(
                claim, status="uncertain", error_code="litellm_projection_outcome_unknown"
            )
        else:
            # An acknowledged projection is not a model verification or publication.
            self._finish(claim, status="applied", error_code=None)

    @staticmethod
    def _invalid_event() -> OutboxPublishError:
        return OutboxPublishError(
            "model_projection_event_invalid", retryable=False, pre_side_effect=True
        )

    @staticmethod
    def _set_state(
        db: Session,
        operation: ModelProjectionOperationRecord,
        status: str,
        code: str | None,
        now: datetime,
        event_id: UUID,
    ) -> None:
        previous = operation.status
        operation.status, operation.error_code, operation.updated_at = status, code, now
        operation.version += 1
        # The receipt policy reads the updated operation in this transaction.
        db.flush()
        db.add(
            ModelProjectionTransitionRecord(
                operation_id=operation.id,
                version=operation.version,
                event_id=event_id,
                actor_principal_id=operation.actor_principal_id,
                previous_status=previous,
                status=status,
                error_code=code,
                occurred_at=now,
            )
        )

    @staticmethod
    def _actor_active(
        db: Session, operation: ModelProjectionOperationRecord, now: datetime
    ) -> bool:
        status = db.scalar(
            sa.select(PlatformStaffPrincipalRecord.status).where(
                PlatformStaffPrincipalRecord.id == operation.actor_principal_id,
            )
        )
        role = db.scalar(
            sa.select(PlatformRoleAssignmentRecord.role)
            .where(
                PlatformRoleAssignmentRecord.principal_id == operation.actor_principal_id,
                PlatformRoleAssignmentRecord.role == "platform_operator",
                PlatformRoleAssignmentRecord.status == "active",
                sa.or_(
                    PlatformRoleAssignmentRecord.expires_at.is_(None),
                    PlatformRoleAssignmentRecord.expires_at > now,
                ),
            )
            .limit(1)
        )
        return status == "active" and role == "platform_operator"

    def _claim(
        self, operation_id: UUID, credential_id: UUID, event_id: UUID
    ) -> _ProjectionClaim | None:
        now = datetime.now(timezone.utc)
        with self._sessions("claim_before_external_write") as db:
            operation = db.scalar(
                sa.select(ModelProjectionOperationRecord)
                .where(
                    ModelProjectionOperationRecord.id == operation_id,
                )
                .with_for_update()
            )
            if (
                operation is None
                or operation.credential_version_id != credential_id
                or operation.action not in {"create_connection", "rotate_credential"}
            ):
                raise self._invalid_event()
            event = db.execute(
                sa.select(
                    ControlPlaneOutboxEvent.tenant_id,
                    ControlPlaneOutboxEvent.aggregate_type,
                    ControlPlaneOutboxEvent.aggregate_key,
                    ControlPlaneOutboxEvent.event_type,
                    ControlPlaneOutboxEvent.payload,
                    ControlPlaneOutboxEvent.request_hash,
                ).where(ControlPlaneOutboxEvent.id == event_id)
            ).one_or_none()
            route = MODEL_CREDENTIAL_PROJECTION_ROUTE
            if event is None or tuple(event) != (
                None,
                route.aggregate_type,
                str(operation_id),
                route.event_type,
                {
                    "event_type": route.payload_event_type,
                    "schema_version": 1,
                    "operation_id": str(operation_id),
                    "credential_version_id": str(credential_id),
                },
                operation.request_hash,
            ):
                raise self._invalid_event()
            if operation.status in {"applied", "verified", "failed", "uncertain"}:
                return None
            if operation.status == "applying":
                self._set_state(
                    db, operation, "uncertain", "litellm_projection_interrupted", now, event_id
                )
                return None
            if operation.status != "requested":
                raise self._invalid_event()
            if not self._actor_active(db, operation, now):
                self._set_state(
                    db, operation, "failed", "model_projection_actor_revoked", now, event_id
                )
                return None
            credential = db.get(ModelCredentialVersionRecord, credential_id)
            if credential is None or credential.connection_id != operation.connection_id:
                raise self._invalid_event()
            try:
                key = self._cipher.decrypt(
                    credential.api_key_ciphertext,
                    context=credential_context(credential.connection_id, credential.id),
                )
                if (
                    not isinstance(key, str)
                    or not 16 <= len(key) <= 4096
                    or not all(33 <= ord(c) <= 126 for c in key)
                ):
                    raise ValueError
            except Exception:  # noqa: BLE001 - KMS exception details remain private.
                self._set_state(
                    db,
                    operation,
                    "failed",
                    "model_projection_credential_unavailable",
                    now,
                    event_id,
                )
                return None
            self._set_state(db, operation, "applying", None, now, event_id)
            return _ProjectionClaim(
                operation.id, operation.version, event_id, credential.credential_name, key
            )

    def _finish(self, claim: _ProjectionClaim, *, status: str, error_code: str | None) -> None:
        with self._sessions("acknowledge_external_write") as db:
            operation = db.scalar(
                sa.select(ModelProjectionOperationRecord)
                .where(
                    ModelProjectionOperationRecord.id == claim.operation_id,
                )
                .with_for_update()
            )
            if operation is None:
                raise OutboxPublishError(
                    "model_projection_receipt_unavailable", retryable=True, pre_side_effect=False
                )
            if operation.status == "applying" and operation.version == claim.operation_version:
                self._set_state(
                    db, operation, status, error_code, datetime.now(timezone.utc), claim.event_id
                )
