"""Governed SMTP configuration shared by Platform Admin and the Outbox worker."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Protocol
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.onboarding import EmailVerificationMessage
from saas.control_plane.platform_models import (
    EmailProviderConfigurationReceiptRecord,
    EmailProviderConfigurationRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context
from saas.onboarding_email import (
    EmailVerificationDeliveryError,
    SmtpConnectionFactory,
    SmtpEmailVerificationConfig,
    SmtpEmailVerificationSender,
)

_PURPOSE = "onboarding_verification"
_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_SECRET_CONTEXT = {
    "workspace_id": "platform",
    "user_id": "system",
    "provider": "smtp",
    "account_id": _PURPOSE,
}


@dataclass(frozen=True, slots=True)
class SmtpConfigurationUpdate:
    enabled: bool
    host: str
    port: int
    security: str
    username: str = field(repr=False)
    password: str | None = field(default=None, repr=False)
    from_address: str = ""
    reply_to_address: str | None = None
    timeout_seconds: float = 10.0


@dataclass(frozen=True, slots=True)
class EmailProviderConfigurationView:
    purpose: str
    configured: bool
    enabled: bool
    host: str | None
    port: int | None
    security: str | None
    username: str | None
    from_address: str | None
    reply_to_address: str | None
    timeout_seconds: float | None
    password_configured: bool
    version: int
    updated_by_principal_id: UUID | None
    updated_at: datetime | None


class SmtpTestSender(Protocol):
    def send_test(
        self,
        *,
        recipient: str,
        configuration_version: int,
        test_id: UUID,
    ) -> None: ...

    def close(self) -> None: ...


class SmtpTestSenderFactory(Protocol):
    def __call__(self, config: SmtpEmailVerificationConfig) -> SmtpTestSender: ...


class EmailProviderConfigurationService:
    """CAS-protected Platform SMTP configuration with non-exporting secret storage."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        authorization: PlatformAuthorizationService,
        secret_cipher: SecretCipher,
        public_origin: str,
        smtp_sender_factory: SmtpTestSenderFactory | None = None,
    ) -> None:
        self._sessions = session_factory
        self._authorization = authorization
        self._cipher = secret_cipher
        self._public_origin = public_origin
        self._smtp_sender_factory = smtp_sender_factory or SmtpEmailVerificationSender

    def get(self, actor: ValidatedPlatformPrincipal) -> EmailProviderConfigurationView:
        self._authorization.require(actor, "platform.email_configuration.read")
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            self._authorization.require_current(
                db,
                actor,
                "platform.email_configuration.read",
                now=_utcnow(),
            )
            return _view(db.get(EmailProviderConfigurationRecord, _PURPOSE))

    def update(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        expected_version: int,
        configuration: SmtpConfigurationUpdate,
        now: datetime | None = None,
    ) -> EmailProviderConfigurationView:
        changed_at = _stored_time(now or _utcnow())
        self._authorization.require(actor, "platform.email_configuration.manage")
        _require_fresh(actor, changed_at)
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            raise PlatformSecurityError(
                "platform_email_configuration_invalid", "SMTP configuration is invalid"
            )
        existing_ciphertext: str | None = None
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            self._authorization.require_current(
                db,
                actor,
                "platform.email_configuration.manage",
                now=changed_at,
            )
            current = db.execute(
                sa.select(EmailProviderConfigurationRecord)
                .where(EmailProviderConfigurationRecord.purpose == _PURPOSE)
                .with_for_update()
            ).scalar_one_or_none()
            current_version = current.version if current is not None else 0
            if expected_version != current_version:
                raise PlatformSecurityError(
                    "platform_email_configuration_conflict",
                    "SMTP configuration changed; reload before saving",
                )
            existing_ciphertext = current.password_ciphertext if current is not None else None
            password = configuration.password
            if password is None and existing_ciphertext is None:
                raise PlatformSecurityError(
                    "platform_email_configuration_invalid",
                    "SMTP password is required for the first configuration",
                )
            validation_password = password if password is not None else "preserved-secret"
            try:
                validated = SmtpEmailVerificationConfig(
                    public_origin=self._public_origin,
                    host=configuration.host,
                    port=configuration.port,
                    security=configuration.security,
                    username=configuration.username,
                    password=validation_password,
                    from_address=configuration.from_address,
                    reply_to_address=configuration.reply_to_address,
                    timeout_seconds=configuration.timeout_seconds,
                )
                ciphertext = (
                    self._cipher.encrypt(password, context=_SECRET_CONTEXT)
                    if password is not None
                    else existing_ciphertext
                )
            except (TypeError, ValueError):
                raise PlatformSecurityError(
                    "platform_email_configuration_invalid", "SMTP configuration is invalid"
                ) from None
            except Exception:  # noqa: BLE001 - redact KMS/Vault backend details.
                raise PlatformSecurityError(
                    "platform_email_secret_unavailable",
                    "SMTP secret encryption is unavailable",
                ) from None
            if ciphertext is None or not ciphertext:
                raise PlatformSecurityError(
                    "platform_email_secret_unavailable", "SMTP secret encryption is unavailable"
                )
            next_version = current_version + 1
            values = {
                "enabled": configuration.enabled,
                "host": validated.host,
                "port": validated.port,
                "security": validated.security,
                "username": validated.username,
                "password_ciphertext": ciphertext,
                "from_address": validated.from_address,
                "reply_to_address": validated.reply_to_address,
                "timeout_seconds": validated.timeout_seconds,
                "version": next_version,
                "updated_by_principal_id": actor.principal_id,
                "updated_at": changed_at,
            }
            if current is None:
                current = EmailProviderConfigurationRecord(purpose=_PURPOSE, **values)
                db.add(current)
            else:
                for name, value in values.items():
                    setattr(current, name, value)
            configuration_hash = _configuration_hash(current)
            db.add(
                EmailProviderConfigurationReceiptRecord(
                    id=uuid4(),
                    purpose=_PURPOSE,
                    configuration_version=next_version,
                    actor_principal_id=actor.principal_id,
                    action="configured" if configuration.enabled else "disabled",
                    configuration_hash=configuration_hash,
                    password_rotated=password is not None,
                    recipient_hash=None,
                    occurred_at=changed_at,
                )
            )
            db.flush()
            return _view(current)

    def send_test(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        recipient: str,
        expected_version: int,
        now: datetime | None = None,
    ) -> None:
        tested_at = _stored_time(now or _utcnow())
        self._authorization.require(actor, "platform.email_configuration.test")
        _require_fresh(actor, tested_at)
        normalized_recipient = _recipient(recipient)
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            self._authorization.require_current(
                db,
                actor,
                "platform.email_configuration.test",
                now=tested_at,
            )
            record = db.get(EmailProviderConfigurationRecord, _PURPOSE)
            if record is None or record.version != expected_version:
                raise PlatformSecurityError(
                    "platform_email_configuration_conflict",
                    "SMTP configuration changed; reload before testing",
                )
            configuration_hash = _configuration_hash(record)
            config = self._decrypt(record)
            version = record.version
        receipt_id = uuid4()
        action = "test_succeeded"
        try:
            sender = self._smtp_sender_factory(config)
            try:
                sender.send_test(
                    recipient=normalized_recipient,
                    configuration_version=version,
                    test_id=receipt_id,
                )
            finally:
                sender.close()
        except EmailVerificationDeliveryError as error:
            action = "test_failed"
            self._record_test(
                actor=actor,
                version=version,
                configuration_hash=configuration_hash,
                recipient=normalized_recipient,
                action=action,
                occurred_at=tested_at,
                receipt_id=receipt_id,
            )
            raise PlatformSecurityError(
                (
                    "platform_email_test_unavailable"
                    if error.retryable
                    else "platform_email_test_rejected"
                ),
                "SMTP test delivery failed",
            ) from None
        self._record_test(
            actor=actor,
            version=version,
            configuration_hash=configuration_hash,
            recipient=normalized_recipient,
            action=action,
            occurred_at=tested_at,
            receipt_id=receipt_id,
        )

    def _decrypt(self, record: EmailProviderConfigurationRecord) -> SmtpEmailVerificationConfig:
        try:
            password = self._cipher.decrypt(
                record.password_ciphertext,
                context=_SECRET_CONTEXT,
            )
            if password is None:
                raise ValueError("SMTP configuration secret is unavailable")
            return _smtp_config(record, password=password, public_origin=self._public_origin)
        except Exception:  # noqa: BLE001 - redact KMS/Vault backend details.
            raise PlatformSecurityError(
                "platform_email_secret_unavailable", "SMTP secret decryption is unavailable"
            ) from None

    def _record_test(
        self,
        *,
        actor: ValidatedPlatformPrincipal,
        version: int,
        configuration_hash: str,
        recipient: str,
        action: str,
        occurred_at: datetime,
        receipt_id: UUID,
    ) -> None:
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            db.add(
                EmailProviderConfigurationReceiptRecord(
                    id=receipt_id,
                    purpose=_PURPOSE,
                    configuration_version=version,
                    actor_principal_id=actor.principal_id,
                    action=action,
                    configuration_hash=configuration_hash,
                    password_rotated=False,
                    recipient_hash=sha256(recipient.encode()).hexdigest(),
                    occurred_at=occurred_at,
                )
            )

    @staticmethod
    def _apply_actor(db: Session, actor: ValidatedPlatformPrincipal) -> None:
        apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))


class EmailProviderConfigurationReader:
    """Worker-side read-only projection of the currently enabled SMTP settings."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        secret_cipher: SecretCipher,
        public_origin: str,
    ) -> None:
        self._sessions = session_factory
        self._cipher = secret_cipher
        self._public_origin = public_origin

    def load(self) -> SmtpEmailVerificationConfig | None:
        with self._sessions.begin() as db:
            record = db.get(EmailProviderConfigurationRecord, _PURPOSE)
            if record is None or not record.enabled:
                return None
            values = {
                "host": record.host,
                "port": record.port,
                "security": record.security,
                "username": record.username,
                "password_ciphertext": record.password_ciphertext,
                "from_address": record.from_address,
                "reply_to_address": record.reply_to_address,
                "timeout_seconds": record.timeout_seconds,
            }
        password = self._cipher.decrypt(
            str(values.pop("password_ciphertext")),
            context=_SECRET_CONTEXT,
        )
        if password is None:
            raise RuntimeError("SMTP configuration secret is unavailable")
        return SmtpEmailVerificationConfig(
            public_origin=self._public_origin,
            password=password,
            **values,  # type: ignore[arg-type]
        )


class ConfiguredSmtpEmailVerificationSender:
    """Resolve the enabled Platform configuration for every Outbox delivery."""

    def __init__(
        self,
        reader: EmailProviderConfigurationReader,
        *,
        connection_factory: SmtpConnectionFactory | None = None,
    ) -> None:
        self._reader = reader
        self._connection_factory = connection_factory

    def close(self) -> None:
        """Connections are scoped to one delivery."""

    def send_verification(
        self,
        *,
        event_id: UUID,
        message: EmailVerificationMessage,
    ) -> None:
        try:
            config = self._reader.load()
        except Exception:  # noqa: BLE001 - collapse config/KMS failure for Outbox retry.
            raise EmailVerificationDeliveryError(
                "email_verification_provider_unavailable",
                retryable=True,
                pre_side_effect=True,
            ) from None
        if config is None:
            raise EmailVerificationDeliveryError(
                "email_verification_provider_not_configured",
                retryable=True,
                pre_side_effect=True,
            )
        sender = SmtpEmailVerificationSender(
            config,
            connection_factory=self._connection_factory,
        )
        try:
            sender.send_verification(event_id=event_id, message=message)
        finally:
            sender.close()


def _smtp_config(
    record: EmailProviderConfigurationRecord,
    *,
    password: str,
    public_origin: str,
) -> SmtpEmailVerificationConfig:
    return SmtpEmailVerificationConfig(
        public_origin=public_origin,
        host=record.host,
        port=record.port,
        security=record.security,
        username=record.username,
        password=password,
        from_address=record.from_address,
        reply_to_address=record.reply_to_address,
        timeout_seconds=record.timeout_seconds,
    )


def _view(
    record: EmailProviderConfigurationRecord | None,
) -> EmailProviderConfigurationView:
    if record is None:
        return EmailProviderConfigurationView(
            purpose=_PURPOSE,
            configured=False,
            enabled=False,
            host=None,
            port=None,
            security=None,
            username=None,
            from_address=None,
            reply_to_address=None,
            timeout_seconds=None,
            password_configured=False,
            version=0,
            updated_by_principal_id=None,
            updated_at=None,
        )
    return EmailProviderConfigurationView(
        purpose=record.purpose,
        configured=True,
        enabled=record.enabled,
        host=record.host,
        port=record.port,
        security=record.security,
        username=record.username,
        from_address=record.from_address,
        reply_to_address=record.reply_to_address,
        timeout_seconds=record.timeout_seconds,
        password_configured=True,
        version=record.version,
        updated_by_principal_id=record.updated_by_principal_id,
        updated_at=_stored_time(record.updated_at),
    )


def _configuration_hash(record: EmailProviderConfigurationRecord) -> str:
    payload = {
        "purpose": record.purpose,
        "enabled": record.enabled,
        "host": record.host,
        "port": record.port,
        "security": record.security,
        "username": record.username,
        "from_address": record.from_address,
        "reply_to_address": record.reply_to_address,
        "timeout_seconds": record.timeout_seconds,
        "version": record.version,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


def _recipient(value: str) -> str:
    normalized = value.strip().lower()
    if (
        value != value.strip()
        or len(value) > 320
        or _EMAIL.fullmatch(value) is None
        or ".." in value
    ):
        raise PlatformSecurityError(
            "platform_email_test_invalid", "SMTP test recipient is invalid"
        )
    return normalized


def _require_fresh(actor: ValidatedPlatformPrincipal, changed_at: datetime) -> None:
    authenticated_at = _stored_time(actor.authenticated_at)
    if authenticated_at > changed_at or changed_at - authenticated_at > _FRESH_AUTH_WINDOW:
        raise PlatformSecurityError(
            "platform_fresh_auth_required", "fresh Staff authentication is required"
        )


def _stored_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "ConfiguredSmtpEmailVerificationSender",
    "EmailProviderConfigurationReader",
    "EmailProviderConfigurationService",
    "EmailProviderConfigurationView",
    "SmtpConfigurationUpdate",
]
