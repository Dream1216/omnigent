"""Publish a tenant catalog version after fresh read-only replica checks."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import sqlalchemy as sa

from omnigent.db.utils import make_named_managed_session_maker
from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.db_models import ControlPlaneOutboxEvent, Tenant
from saas.control_plane.litellm_client import LiteLLMManagementConfiguration
from saas.control_plane.model_connections import credential_context
from saas.control_plane.model_deployments import (
    CompiledModelDeploymentDraft,
    compile_stored_model_deployment,
)
from saas.control_plane.model_pricing import PlatformModelPricingPolicy
from saas.control_plane.model_projection import ModelCredentialProjectionPublisher
from saas.control_plane.model_publications import (
    PUBLICATION_EVENT,
    current_publication_generation,
    lock_publication_scope,
    publication_snapshot,
    verified_publication_plan,
)
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelPublicationCommandRecord,
    ModelPublicationVersionRecord,
)
from saas.control_plane.model_verification_contract import canonical_verification_document
from saas.control_plane.outbox import OutboxClaimRoute, OutboxPublishError
from saas.control_plane.platform_models import (
    PlatformAuthSessionRecord,
    PlatformStaffPrincipalRecord,
)
from saas.control_plane.platform_security import PlatformSecurityError
from saas.production.litellm_replica_readiness import (
    LiteLLMReplicaEndpoint,
    LiteLLMReplicaReadinessAuthority,
    LiteLLMReplicaReadinessError,
)
from saas.production.onboarding import _read_bytes, _regular_file

MODEL_PUBLICATION_ROUTE = OutboxClaimRoute(
    aggregate_type="platform_model",
    event_type=PUBLICATION_EVENT,
    payload_event_type=PUBLICATION_EVENT,
)


def model_publication_enabled(source: Mapping[str, str]) -> bool:
    value = source.get("OMNIGENT_SAAS_MODEL_PUBLICATION_ENABLED", "false")
    if value not in {"true", "false"}:
        raise ValueError("model_publication_flag_invalid")
    return value == "true"


def load_litellm_replica_inventory(
    source: Mapping[str, str], *, management: LiteLLMManagementConfiguration
) -> tuple[LiteLLMReplicaEndpoint, ...]:
    """Read the operator-mounted inventory, not a browser-supplied fleet assertion."""
    name = "OMNIGENT_SAAS_LITELLM_REPLICA_INVENTORY_FILE"
    try:
        path = _regular_file(source, name, maximum_bytes=16384)
        document = json.loads(_read_bytes(path, name, maximum_bytes=16384))
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "source_sha", "replicas"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or re.fullmatch(r"[0-9a-f]{40}", document["source_sha"]) is None
            or document["source_sha"] != source.get("OMNIGENT_SAAS_SOURCE_SHA")
            or not isinstance(document["replicas"], list)
            or not 2 <= len(document["replicas"]) <= 16
        ):
            raise ValueError
        replicas = []
        for row in document["replicas"]:
            if not isinstance(row, dict) or set(row) != {"replica_id", "base_url"}:
                raise ValueError
            host = urlsplit(row["base_url"]).hostname or ""
            allowed = (
                (host,)
                if host.endswith(
                    (
                        ".omnigent-next-beta.pod.cluster.local",
                        ".omnigent-litellm.omnigent-next-beta.svc.cluster.local",
                    )
                )
                else ()
            )
            replicas.append(
                LiteLLMReplicaEndpoint(
                    row["replica_id"],
                    LiteLLMManagementConfiguration(
                        base_url=row["base_url"],
                        management_key=management.management_key,
                        allowed_http_hosts=allowed,
                    ),
                )
            )
        return tuple(replicas)
    except Exception:  # noqa: BLE001 - mounted inventory and transport details stay private
        raise ValueError("model_publication_inventory_invalid") from None


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class _Stopped(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _Claim:
    operation_id: UUID
    operation_version: int
    event_id: UUID
    draft: CompiledModelDeploymentDraft


class ModelPublicationPublisher:
    def __init__(
        self,
        engine: sa.Engine,
        *,
        secret_cipher: SecretCipher,
        readiness: LiteLLMReplicaReadinessAuthority,
        pricing: PlatformModelPricingPolicy,
    ):
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_publication_worker", immediate=True
        )
        self._cipher, self._readiness, self._pricing = secret_cipher, readiness, pricing

    @staticmethod
    def _invalid():
        return OutboxPublishError(
            "model_publication_event_invalid", retryable=False, pre_side_effect=True
        )

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        if (
            event_id.int == 0
            or event_type != PUBLICATION_EVENT
            or aggregate_type != "platform_model"
            or set(payload)
            != {"event_type", "schema_version", "operation_id", "credential_version_id"}
            or payload.get("event_type") != PUBLICATION_EVENT
            or type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != 1
            or payload.get("operation_id") != aggregate_key
        ):
            raise self._invalid()
        try:
            operation_id, credential_id = (
                UUID(aggregate_key),
                UUID(str(payload["credential_version_id"])),
            )
        except (ValueError, TypeError, AttributeError):
            raise self._invalid() from None
        claim = None
        try:
            claim = self._claim(operation_id, credential_id, event_id)
            if claim is None:
                return
            with self._session("read_canonical_publication_inputs") as db:
                operation, command = self._live(db, claim)
                verified_publication_plan(
                    db, claim.draft, command.verification_operation_id, self._pricing
                )
                credential = db.get(ModelCredentialVersionRecord, credential_id)
                if credential is None:
                    raise _Stopped
                name = credential.credential_name
                key = self._cipher.decrypt(
                    credential.api_key_ciphertext,
                    context=credential_context(operation.connection_id, credential_id),
                )
                if not isinstance(key, str) or not key:
                    raise _Stopped
            proof = asyncio.run(
                self._readiness.attest(
                    draft=claim.draft, credential_name=name, expected_api_key=key
                )
            )
            with self._session("commit_one_tenant_publication_version") as db:
                operation, command = self._live(db, claim)
                lock_publication_scope(db, command.tenant_id, claim.draft)
                if (
                    current_publication_generation(db, command.tenant_id, claim.draft)
                    != command.expected_generation
                ):
                    raise PlatformSecurityError(
                        "platform_model_publication_conflict", "Publication changed"
                    )
                plan = verified_publication_plan(
                    db, claim.draft, command.verification_operation_id, self._pricing
                )
                at = datetime.now(timezone.utc)
                proof.require_current(
                    draft=claim.draft, inventory_sha256=self._readiness.inventory_sha256, now=at
                )
                snapshot = publication_snapshot(claim.draft, command, plan)
                readiness = canonical_verification_document(proof.evidence())
                db.add(
                    ModelPublicationVersionRecord(
                        id=uuid4(),
                        operation_id=operation.id,
                        tenant_id=command.tenant_id,
                        deployment_version_id=claim.draft.deployment_id,
                        public_model_id=claim.draft.public_model_id,
                        wire_api=claim.draft.wire_api,
                        generation=command.expected_generation + 1,
                        configuration_sha256=claim.draft.configuration_sha256,
                        price_sha256=plan.price_sha256,
                        inventory_sha256=proof.inventory_sha256,
                        canonical_snapshot=snapshot,
                        snapshot_sha256=sha256(snapshot.encode("ascii")).hexdigest(),
                        canonical_readiness=readiness,
                        readiness_sha256=sha256(readiness.encode("ascii")).hexdigest(),
                        created_at=at,
                    )
                )
                # The state-transition guard requires the immutable receipt first.
                db.flush()
                ModelCredentialProjectionPublisher._set_state(
                    db, operation, "applied", None, at, event_id
                )
        except sa.exc.SQLAlchemyError:
            raise OutboxPublishError(
                "model_publication_storage_unavailable", retryable=True, pre_side_effect=False
            ) from None
        except LiteLLMReplicaReadinessError as error:
            if error.code == "litellm_replica_readiness_unavailable":
                raise OutboxPublishError(
                    "model_publication_waiting_for_replicas", retryable=True, pre_side_effect=True
                ) from None
            if claim is not None:
                self._fail(claim, error.code)
        except PlatformSecurityError as error:
            if claim is not None:
                self._fail(claim, error.code)
        except _Stopped:
            if claim is not None:
                self._fail(claim, "model_publication_authority_changed")
        except OutboxPublishError:
            raise
        except Exception:  # noqa: BLE001 - retain a redacted terminal receipt at the Worker boundary
            if claim is not None:
                self._fail(claim, "model_publication_inputs_unavailable")
            else:
                raise self._invalid() from None

    def _claim(self, operation_id: UUID, credential_id: UUID, event_id: UUID) -> _Claim | None:
        with self._session("claim_read_only_publication_operation") as db:
            operation = db.scalar(
                sa.select(ModelProjectionOperationRecord)
                .where(ModelProjectionOperationRecord.id == operation_id)
                .with_for_update()
            )
            command = db.get(ModelPublicationCommandRecord, operation_id)
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
            if (
                operation is None
                or command is None
                or operation.action != "publish_deployment"
                or operation.credential_version_id != credential_id
                or event is None
                or tuple(event)
                != (
                    None,
                    "platform_model",
                    str(operation_id),
                    PUBLICATION_EVENT,
                    {
                        "event_type": PUBLICATION_EVENT,
                        "schema_version": 1,
                        "operation_id": str(operation_id),
                        "credential_version_id": str(credential_id),
                    },
                    operation.request_hash,
                )
            ):
                raise self._invalid()
            if operation.status in {"applied", "failed", "uncertain"}:
                return None
            row = db.get(ModelDeploymentVersionRecord, operation.deployment_version_id)
            if row is None or operation.status not in {"requested", "applying"}:
                raise self._invalid()
            draft = compile_stored_model_deployment(row)
            if operation.status == "requested":
                ModelCredentialProjectionPublisher._set_state(
                    db, operation, "applying", None, datetime.now(timezone.utc), event_id
                )
            return _Claim(operation.id, operation.version, event_id, draft)

    def _live(self, db, claim):
        operation = db.scalar(
            sa.select(ModelProjectionOperationRecord)
            .where(ModelProjectionOperationRecord.id == claim.operation_id)
            .with_for_update()
        )
        command = db.get(ModelPublicationCommandRecord, claim.operation_id)
        now = datetime.now(timezone.utc)
        if (
            operation is None
            or command is None
            or operation.status != "applying"
            or operation.version != claim.operation_version
            or _aware(command.expires_at) <= now
            or not ModelCredentialProjectionPublisher._actor_active(db, operation, now)
        ):
            raise _Stopped
        session = db.execute(
            sa.select(
                PlatformAuthSessionRecord.principal_id,
                PlatformAuthSessionRecord.security_version,
                PlatformAuthSessionRecord.authenticated_at,
                PlatformAuthSessionRecord.expires_at,
                PlatformAuthSessionRecord.revoked_at,
            ).where(PlatformAuthSessionRecord.id == command.staff_session_id)
        ).one_or_none()
        security = db.scalar(
            sa.select(PlatformStaffPrincipalRecord.security_version).where(
                PlatformStaffPrincipalRecord.id == operation.actor_principal_id
            )
        )
        status = db.scalar(sa.select(Tenant.status).where(Tenant.id == command.tenant_id))
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
        if (
            session is None
            or session.principal_id != operation.actor_principal_id
            or session.security_version != command.staff_security_version
            or security != session.security_version
            or session.revoked_at is not None
            or _aware(session.expires_at) <= now
            or _aware(session.authenticated_at) > now
            or (now - _aware(session.authenticated_at)).total_seconds() >= 300
            or status not in {"trial", "active"}
            or generation is None
            or generation != credential_generation
        ):
            raise _Stopped
        return operation, command

    def _fail(self, claim: _Claim, code: str) -> None:
        if not isinstance(code, str) or re.fullmatch(r"[a-z0-9_]{1,128}", code) is None:
            code = "model_publication_inputs_unavailable"
        with self._session("retain_publication_failure_without_catalog_mutation") as db:
            operation = db.scalar(
                sa.select(ModelProjectionOperationRecord)
                .where(ModelProjectionOperationRecord.id == claim.operation_id)
                .with_for_update()
            )
            if (
                operation is not None
                and operation.status == "applying"
                and operation.version == claim.operation_version
            ):
                ModelCredentialProjectionPublisher._set_state(
                    db, operation, "failed", code, datetime.now(timezone.utc), claim.event_id
                )
