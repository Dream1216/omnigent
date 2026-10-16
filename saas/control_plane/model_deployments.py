"""Secret-free immutable draft compilation; a draft is never runtime admission."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid4

import sqlalchemy as sa

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_connections import (
    _IDEMPOTENCY,
    ModelProjectionOperationView,
    _operation_view,
    authorize_platform_model_operation,
    lock_model_operation_idempotency,
)
from saas.control_plane.model_provider import _MODEL_ID
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.runner_adapter.platform_models import PLATFORM_MODEL_MAX_OUTPUT_TOKENS

ModelWireApi = Literal["openai_chat_completions", "openai_responses"]


class ModelDeploymentValidationError(ValueError):
    """Stable validation code; never serialize caller input in an error."""


@dataclass(frozen=True, slots=True)
class CreateModelDeploymentDraft:
    public_model_id: str
    display_name: str
    connection_id: UUID
    credential_version_id: UUID
    expected_generation: int
    wire_api: ModelWireApi
    max_output_tokens: int


@dataclass(frozen=True, slots=True)
class CompiledModelDeploymentDraft:
    deployment_id: UUID
    alias: str
    public_model_id: str
    display_name: str
    connection_id: UUID
    credential_version_id: UUID
    generation: int
    wire_api: ModelWireApi
    max_output_tokens: int
    request_hash: str
    configuration_sha256: str
    canonical_configuration: str

    @property
    def runtime_enabled(self) -> Literal[False]:
        return False

    @property
    def verification_status(self) -> Literal["not_tested"]:
        return "not_tested"

    def configuration_document(self) -> dict[str, object]:
        """Return a disposable view without making the hashed draft mutable."""

        return json.loads(self.canonical_configuration)


def _canonical(document: dict[str, object]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compile_model_deployment_draft(
    command: CreateModelDeploymentDraft, *, deployment_id: UUID
) -> CompiledModelDeploymentDraft:
    """Compile metadata only; authorization and persistence belong to admission."""

    if (
        not isinstance(command.public_model_id, str)
        or _MODEL_ID.fullmatch(command.public_model_id) is None
        or not isinstance(command.display_name, str)
        or not 1 <= len(command.display_name) <= 128
        or command.display_name != command.display_name.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in command.display_name)
        or any(
            not isinstance(value, UUID) or value.int == 0
            for value in (deployment_id, command.connection_id, command.credential_version_id)
        )
        or type(command.expected_generation) is not int
        or not 0 <= command.expected_generation < (1 << 31) - 1
        or not isinstance(command.wire_api, str)
        or command.wire_api not in {"openai_chat_completions", "openai_responses"}
        or type(command.max_output_tokens) is not int
        or not 1 <= command.max_output_tokens <= PLATFORM_MODEL_MAX_OUTPUT_TOKENS
    ):
        raise ModelDeploymentValidationError("platform_model_deployment_invalid")
    generation = command.expected_generation + 1
    # The public ID stays unchanged; the private alias identifies one immutable deployment.
    alias = "platform-model-" + deployment_id.hex
    request: dict[str, object] = {
        "action": "create_deployment",
        "schema_version": 1,
        "provider_id": "deepseek",
        "public_model_id": command.public_model_id,
        "display_name": command.display_name,
        "connection_id": str(command.connection_id),
        "credential_version_id": str(command.credential_version_id),
        "expected_generation": command.expected_generation,
        "wire_api": command.wire_api,
        "max_output_tokens": command.max_output_tokens,
    }
    configuration: dict[str, object] = {
        "schema_version": 1,
        "deployment_id": str(deployment_id),
        "alias": alias,
        "provider_id": "deepseek",
        "provider_base_url": "https://api.deepseek.com",
        "provider_model": command.public_model_id,
        "public_model_id": command.public_model_id,
        "display_name": command.display_name,
        "connection_id": str(command.connection_id),
        "credential_version_id": str(command.credential_version_id),
        "generation": generation,
        "wire_api": command.wire_api,
        "max_output_tokens": command.max_output_tokens,
        "num_retries": 0,
        "max_retries": 0,
    }
    canonical = _canonical(configuration)
    return CompiledModelDeploymentDraft(
        deployment_id,
        alias,
        command.public_model_id,
        command.display_name,
        command.connection_id,
        command.credential_version_id,
        generation,
        command.wire_api,
        command.max_output_tokens,
        sha256(_canonical(request).encode("ascii")).hexdigest(),
        sha256(canonical.encode("ascii")).hexdigest(),
        canonical,
    )


@dataclass(frozen=True, slots=True)
class ModelCredentialVersionMetadata:
    id: UUID
    generation: int
    projected: bool


@dataclass(frozen=True, slots=True)
class ModelDeploymentVersionView:
    id: UUID
    public_model_id: str
    display_name: str
    connection_id: UUID
    credential_version_id: UUID
    generation: int
    wire_api: str
    max_output_tokens: int
    configuration_sha256: str
    operation_id: UUID
    projection_status: str
    runtime_enabled: bool = False
    verification_status: str = "not_tested"


class ModelDeploymentService:
    """Persist one immutable draft and its projection request in the same database."""

    def __init__(self, engine: sa.Engine, *, authorization: PlatformAuthorizationService) -> None:
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_deployments", immediate=True
        )
        self._authorization = authorization

    def credential_versions(
        self, actor: ValidatedPlatformPrincipal, connection_id: UUID
    ) -> tuple[ModelCredentialVersionMetadata, ...]:
        with self._session("list_credential_version_metadata") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.manage",
                datetime.now(timezone.utc),
            )
            rows = db.execute(
                sa.select(
                    ModelCredentialVersionRecord.id,
                    ModelCredentialVersionRecord.generation,
                    sa.func.max(
                        sa.case((ModelProjectionOperationRecord.status == "applied", 1), else_=0)
                    ),
                )
                .join(
                    ModelProjectionOperationRecord,
                    sa.and_(
                        ModelProjectionOperationRecord.credential_version_id
                        == ModelCredentialVersionRecord.id,
                        ModelProjectionOperationRecord.action.in_(
                            ("create_connection", "rotate_credential")
                        ),
                    ),
                )
                .where(ModelCredentialVersionRecord.connection_id == connection_id)
                .group_by(ModelCredentialVersionRecord.id, ModelCredentialVersionRecord.generation)
                .order_by(ModelCredentialVersionRecord.generation.desc())
                .limit(100)
            ).all()
            return tuple(
                ModelCredentialVersionMetadata(identifier, generation, bool(applied))
                for identifier, generation, applied in rows
            )

    def list(self, actor: ValidatedPlatformPrincipal) -> tuple[ModelDeploymentVersionView, ...]:
        with self._session("list_deployment_drafts") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            rows = db.execute(
                sa.select(ModelDeploymentVersionRecord, ModelProjectionOperationRecord)
                .join(
                    ModelProjectionOperationRecord,
                    sa.and_(
                        ModelProjectionOperationRecord.deployment_version_id
                        == ModelDeploymentVersionRecord.id,
                        ModelProjectionOperationRecord.action == "create_deployment",
                    ),
                )
                .order_by(
                    ModelDeploymentVersionRecord.created_at.desc(), ModelDeploymentVersionRecord.id
                )
                .limit(100)
            ).all()
            return tuple(
                ModelDeploymentVersionView(
                    record.id,
                    record.public_model_id,
                    record.display_name,
                    record.connection_id,
                    record.credential_version_id,
                    record.generation,
                    record.wire_api,
                    record.max_output_tokens,
                    record.configuration_sha256,
                    operation.id,
                    operation.status,
                )
                for record, operation in rows
            )

    def create(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        command: CreateModelDeploymentDraft,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ModelProjectionOperationView:
        try:
            compiled = compile_model_deployment_draft(command, deployment_id=uuid4())
        except ModelDeploymentValidationError:
            raise PlatformSecurityError(
                "platform_model_deployment_invalid", "Model draft is invalid"
            ) from None
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise PlatformSecurityError(
                "platform_model_deployment_invalid", "Model draft is invalid"
            )
        timestamp = now or datetime.now(timezone.utc)
        with self._session("admit_immutable_deployment_draft") as db:
            authorize_platform_model_operation(
                db, self._authorization, actor, "platform.model_provider.manage", timestamp
            )
            lock_model_operation_idempotency(db, actor.principal_id)
            prior = db.scalar(
                sa.select(ModelProjectionOperationRecord).where(
                    ModelProjectionOperationRecord.actor_principal_id == actor.principal_id,
                    ModelProjectionOperationRecord.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                if (
                    prior.action != "create_deployment"
                    or prior.request_hash != compiled.request_hash
                ):
                    raise PlatformSecurityError(
                        "platform_model_operation_conflict",
                        "Idempotency key was used for another command",
                    )
                return _operation_view(prior)
            if db.get_bind().dialect.name == "postgresql":
                lock_id = int.from_bytes(
                    sha256(("model-deployment:" + command.public_model_id).encode()).digest()[:8],
                    "big",
                    signed=True,
                )
                db.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_id})
            generation = (
                db.scalar(
                    sa.select(sa.func.max(ModelDeploymentVersionRecord.generation)).where(
                        ModelDeploymentVersionRecord.public_model_id == command.public_model_id,
                    )
                )
                or 0
            )
            if generation != command.expected_generation:
                raise PlatformSecurityError(
                    "platform_model_deployment_conflict",
                    "Model draft changed; reload before saving",
                )
            connection = db.scalar(
                sa.select(ModelConnectionRecord)
                .where(
                    ModelConnectionRecord.id == command.connection_id,
                )
                .with_for_update()
            )
            credential = db.get(ModelCredentialVersionRecord, command.credential_version_id)
            applied = db.scalar(
                sa.select(ModelProjectionOperationRecord.id)
                .where(
                    ModelProjectionOperationRecord.connection_id == command.connection_id,
                    ModelProjectionOperationRecord.credential_version_id
                    == command.credential_version_id,
                    ModelProjectionOperationRecord.action.in_(
                        ("create_connection", "rotate_credential")
                    ),
                    ModelProjectionOperationRecord.status == "applied",
                )
                .limit(1)
            )
            if (
                connection is None
                or credential is None
                or applied is None
                or credential.connection_id != connection.id
                or credential.generation != connection.credential_generation
            ):
                raise PlatformSecurityError(
                    "platform_model_credential_not_projected",
                    "Select the current acknowledged credential version",
                )
            db.add(
                ModelDeploymentVersionRecord(
                    id=compiled.deployment_id,
                    public_model_id=compiled.public_model_id,
                    display_name=compiled.display_name,
                    provider_model=compiled.public_model_id,
                    connection_id=compiled.connection_id,
                    credential_version_id=compiled.credential_version_id,
                    generation=compiled.generation,
                    deployment_alias=compiled.alias,
                    wire_api=compiled.wire_api,
                    max_output_tokens=compiled.max_output_tokens,
                    configuration_sha256=compiled.configuration_sha256,
                    canonical_configuration=compiled.canonical_configuration,
                    created_by_principal_id=actor.principal_id,
                    created_at=timestamp,
                )
            )
            operation = ModelProjectionOperationRecord(
                id=uuid4(),
                connection_id=compiled.connection_id,
                credential_version_id=compiled.credential_version_id,
                deployment_version_id=compiled.deployment_id,
                action="create_deployment",
                actor_principal_id=actor.principal_id,
                idempotency_key=idempotency_key,
                request_hash=compiled.request_hash,
                status="requested",
                version=1,
                created_at=timestamp,
                updated_at=timestamp,
            )
            db.add(operation)
            # The Outbox row policy verifies the admitted operation in this transaction.
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=None,
                    aggregate_type="platform_model",
                    aggregate_key=str(operation.id),
                    event_type="platform.model_projection.requested",
                    idempotency_key="model-projection:" + operation.id.hex,
                    request_hash=operation.request_hash,
                    created_at=timestamp,
                    payload={
                        "event_type": "platform.model_projection.requested",
                        "operation_id": str(operation.id),
                        "credential_version_id": str(operation.credential_version_id),
                        "schema_version": 1,
                    },
                )
            )
            return _operation_view(operation)
