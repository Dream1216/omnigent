"""Staff-only connection admission with encrypted credentials and one Outbox."""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.stores.credential_store.secret_cipher import SecretCipher, SecretContext
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelProjectionOperationRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

_IDEMPOTENCY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}")


@dataclass(frozen=True, slots=True)
class CreateModelConnection:
    display_name: str
    api_key: str = field(repr=False)
    provider_id: str = "deepseek"
    base_url: str = "https://api.deepseek.com"


@dataclass(frozen=True, slots=True)
class ModelConnectionView:
    id: UUID
    display_name: str
    provider_id: str
    base_url: str
    version: int
    credential_generation: int
    credential_configured: bool
    runtime_enabled: bool = False


@dataclass(frozen=True, slots=True)
class ModelProjectionOperationView:
    id: UUID
    connection_id: UUID
    credential_version_id: UUID
    action: str
    status: str
    error_code: str | None
    version: int
    deployment_version_id: UUID | None = None


def authorize_platform_model_operation(
    db: Session,
    authorization: PlatformAuthorizationService,
    actor: ValidatedPlatformPrincipal,
    permission: str,
    now: datetime,
) -> None:
    """Bind the current Staff identity and preserve the same fresh-auth fence."""

    if now.tzinfo is None or actor.expires_at <= now:
        raise PlatformSecurityError("platform_session_expired", "Staff session has expired")
    apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))
    authorization.require_current(db, actor, permission, now=now)
    if permission == "platform.model_provider.manage" and (
        actor.authenticated_at > now or now - actor.authenticated_at > timedelta(minutes=5)
    ):
        raise PlatformSecurityError(
            "platform_fresh_auth_required", "Fresh Staff authentication is required"
        )


def lock_model_operation_idempotency(db: Session, principal_id: UUID) -> None:
    """Serialize the actor's shared connection/deployment command namespace."""

    if db.get_bind().dialect.name == "postgresql":
        lock_id = int.from_bytes(
            sha256(str(principal_id).encode()).digest()[:8], "big", signed=True
        )
        db.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_id})


def credential_context(connection_id: UUID, credential_id: UUID) -> SecretContext:
    return {
        "workspace_id": "platform",
        "user_id": "system",
        "provider": "deepseek",
        "account_id": f"model_connection:{connection_id}:{credential_id}",
    }


def _invalid() -> PlatformSecurityError:
    return PlatformSecurityError(
        "platform_model_connection_invalid", "Model connection command is invalid"
    )


def _validate_key(value: str) -> None:
    if (
        not isinstance(value, str)
        or not 16 <= len(value) <= 4096
        or not all(33 <= ord(c) <= 126 for c in value)
    ):
        raise _invalid()


def _connection_view(record: ModelConnectionRecord) -> ModelConnectionView:
    return ModelConnectionView(
        record.id,
        record.display_name,
        record.provider_id,
        record.base_url,
        record.version,
        record.credential_generation,
        True,
    )


def _operation_view(record: ModelProjectionOperationRecord) -> ModelProjectionOperationView:
    return ModelProjectionOperationView(
        record.id,
        record.connection_id,
        record.credential_version_id,
        record.action,
        record.status,
        record.error_code,
        record.version,
        record.deployment_version_id,
    )


class ModelConnectionService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        authorization: PlatformAuthorizationService,
        secret_cipher: SecretCipher,
    ) -> None:
        self._sessions, self._authorization, self._cipher = (
            session_factory,
            authorization,
            secret_cipher,
        )

    def _authorize(
        self,
        db: Session,
        actor: ValidatedPlatformPrincipal,
        permission: str,
        now: datetime,
    ) -> None:
        authorize_platform_model_operation(db, self._authorization, actor, permission, now)

    def list(self, actor: ValidatedPlatformPrincipal) -> tuple[ModelConnectionView, ...]:
        with self._sessions.begin() as db:
            self._authorize(db, actor, "platform.model_provider.read", datetime.now(timezone.utc))
            rows = db.scalars(
                sa.select(ModelConnectionRecord)
                .order_by(ModelConnectionRecord.created_at, ModelConnectionRecord.id)
                .limit(100)
            )
            return tuple(_connection_view(record) for record in rows)

    def operation(
        self, actor: ValidatedPlatformPrincipal, operation_id: UUID
    ) -> ModelProjectionOperationView:
        with self._sessions.begin() as db:
            self._authorize(db, actor, "platform.model_provider.read", datetime.now(timezone.utc))
            record = db.get(ModelProjectionOperationRecord, operation_id)
            if record is None:
                raise PlatformSecurityError(
                    "platform_model_operation_not_found", "Model operation was not found"
                )
            return _operation_view(record)

    def find_operation(
        self, actor: ValidatedPlatformPrincipal, idempotency_key: str
    ) -> ModelProjectionOperationView | None:
        if _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise _invalid()
        with self._sessions.begin() as db:
            self._authorize(db, actor, "platform.model_provider.read", datetime.now(timezone.utc))
            record = db.scalar(
                sa.select(ModelProjectionOperationRecord).where(
                    ModelProjectionOperationRecord.actor_principal_id == actor.principal_id,
                    ModelProjectionOperationRecord.idempotency_key == idempotency_key,
                )
            )
            return None if record is None else _operation_view(record)

    def create(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        command: CreateModelConnection,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ModelProjectionOperationView:
        if (
            not isinstance(command.display_name, str)
            or not 1 <= len(command.display_name) <= 128
            or command.display_name != command.display_name.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in command.display_name)
            or command.provider_id != "deepseek"
            or command.base_url != "https://api.deepseek.com"
        ):
            raise _invalid()
        return self._admit(
            actor,
            action="create_connection",
            idempotency_key=idempotency_key,
            api_key=command.api_key,
            material={
                "display_name": command.display_name,
                "provider_id": command.provider_id,
                "base_url": command.base_url,
            },
            connection_id=None,
            expected_version=0,
            now=now or datetime.now(timezone.utc),
        )

    def rotate_credential(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        connection_id: UUID,
        expected_version: int,
        api_key: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ModelProjectionOperationView:
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 1
        ):
            raise _invalid()
        return self._admit(
            actor,
            action="rotate_credential",
            idempotency_key=idempotency_key,
            api_key=api_key,
            material={"connection_id": str(connection_id), "expected_version": expected_version},
            connection_id=connection_id,
            expected_version=expected_version,
            now=now or datetime.now(timezone.utc),
        )

    def _admit(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        action: str,
        idempotency_key: str,
        api_key: str,
        material: dict[str, object],
        connection_id: UUID | None,
        expected_version: int,
        now: datetime,
    ) -> ModelProjectionOperationView:
        _validate_key(api_key)
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise _invalid()
        request_hash = sha256(
            json.dumps(
                {"action": action, **material}, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        with self._sessions.begin() as db:
            self._authorize(db, actor, "platform.model_provider.manage", now)
            # Serialize this actor's admissions before reading the idempotency receipt.
            lock_model_operation_idempotency(db, actor.principal_id)
            prior = db.scalar(
                sa.select(ModelProjectionOperationRecord).where(
                    ModelProjectionOperationRecord.actor_principal_id == actor.principal_id,
                    ModelProjectionOperationRecord.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                credential = db.get(ModelCredentialVersionRecord, prior.credential_version_id)
                if prior.request_hash != request_hash or credential is None:
                    raise PlatformSecurityError(
                        "platform_model_operation_conflict",
                        "Idempotency key was used for another command",
                    )
                plaintext = self._decrypt(credential)
                if not hmac.compare_digest(plaintext, api_key):
                    raise PlatformSecurityError(
                        "platform_model_operation_conflict",
                        "Idempotency key was used for another command",
                    )
                return _operation_view(prior)
            connection = (
                None
                if connection_id is None
                else db.scalar(
                    sa.select(ModelConnectionRecord)
                    .where(ModelConnectionRecord.id == connection_id)
                    .with_for_update()
                )
            )
            if connection_id is not None and connection is None:
                raise PlatformSecurityError(
                    "platform_model_connection_not_found", "Model connection was not found"
                )
            if connection is not None and connection.version != expected_version:
                raise PlatformSecurityError(
                    "platform_model_connection_conflict",
                    "Model connection changed; reload before saving",
                )
            if connection is None:
                connection = ModelConnectionRecord(
                    id=uuid4(),
                    display_name=str(material["display_name"]),
                    provider_id="deepseek",
                    base_url="https://api.deepseek.com",
                    version=1,
                    credential_generation=1,
                    updated_by_principal_id=actor.principal_id,
                    created_at=now,
                    updated_at=now,
                )
                db.add(connection)
            else:
                connection.version += 1
                connection.credential_generation += 1
                connection.updated_by_principal_id, connection.updated_at = actor.principal_id, now
            credential_id, operation_id = uuid4(), uuid4()
            try:
                ciphertext = self._cipher.encrypt(
                    api_key, context=credential_context(connection.id, credential_id)
                )
                if not ciphertext:
                    raise ValueError
            except Exception:  # noqa: BLE001 - KMS failures must not disclose secret details.
                raise PlatformSecurityError(
                    "platform_model_secret_unavailable", "Model secret storage is unavailable"
                ) from None
            db.add(
                ModelCredentialVersionRecord(
                    id=credential_id,
                    connection_id=connection.id,
                    generation=connection.credential_generation,
                    credential_name="platform-credential-" + credential_id.hex,
                    api_key_ciphertext=ciphertext,
                    created_by_principal_id=actor.principal_id,
                    created_at=now,
                )
            )
            operation = ModelProjectionOperationRecord(
                id=operation_id,
                connection_id=connection.id,
                credential_version_id=credential_id,
                actor_principal_id=actor.principal_id,
                action=action,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                status="requested",
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(operation)
            # The Outbox policy requires its admitted operation to exist already.
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=None,
                    aggregate_type="platform_model",
                    aggregate_key=str(operation_id),
                    event_type="platform.model_projection.requested",
                    payload={
                        "event_type": "platform.model_projection.requested",
                        "operation_id": str(operation_id),
                        "credential_version_id": str(credential_id),
                        "schema_version": 1,
                    },
                    idempotency_key="model-projection:" + operation_id.hex,
                    request_hash=request_hash,
                    created_at=now,
                )
            )
            return _operation_view(operation)

    def _decrypt(self, credential: ModelCredentialVersionRecord) -> str:
        try:
            value = self._cipher.decrypt(
                credential.api_key_ciphertext,
                context=credential_context(credential.connection_id, credential.id),
            )
            if not value:
                raise ValueError
            _validate_key(value)
            return value
        except Exception:  # noqa: BLE001 - ciphertext and KMS details are never API errors.
            raise PlatformSecurityError(
                "platform_model_secret_unavailable", "Model secret storage is unavailable"
            ) from None
