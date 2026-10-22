"""Production adapters for the notification delivery worker."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import jwt
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import GlobalUser
from saas.control_plane.notification_delivery import (
    DeliveryProviderReceipt,
    NotificationChannel,
    NotificationDeliveryError,
    NotificationDeliveryService,
    NotificationErrorDigester,
    NotificationTemplateCatalog,
    NotificationWorkloadIdentity,
    ResolvedRecipient,
    ResolvedRenderContext,
)
from saas.control_plane.notification_events import (
    DatabasePlatformNotificationAudience,
    DeadLetterNotificationSink,
)
from saas.control_plane.notification_templates import (
    PackagedNotificationTemplateCatalog,
)
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord


@dataclass(frozen=True, slots=True)
class JwtNotificationWorkloadIdentityProvider:
    """Verify a projected service-account JWT against the configured issuer JWKS."""

    token_file: Path
    issuer: str
    jwks_url: str
    audience: str = "omnigent:notification-delivery"
    subject_prefix: str = "spiffe://"
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    _jwk_client: jwt.PyJWKClient = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not self.token_file.is_absolute()
            or not self.issuer.startswith("https://")
            or not self.jwks_url.startswith("https://")
            or not self.audience
            or not self.subject_prefix
        ):
            raise ValueError("notification workload identity configuration is invalid")
        object.__setattr__(self, "_jwk_client", jwt.PyJWKClient(self.jwks_url))

    def identity(self, *, now: datetime) -> NotificationWorkloadIdentity:
        at = _aware(now)
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
            if not token or len(token) > 16_384:
                raise ValueError("invalid token size")
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["sub", "iat", "exp", "iss", "aud"]},
            )
            subject = str(claims["sub"])
            authenticated_at = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
            expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
        except (OSError, KeyError, TypeError, ValueError, jwt.PyJWTError) as error:
            raise NotificationDeliveryError("notification_workload_identity_invalid") from error
        if (
            not subject.startswith(self.subject_prefix)
            or authenticated_at > at
            or expires_at <= at
        ):
            raise NotificationDeliveryError("notification_workload_identity_invalid")
        return NotificationWorkloadIdentity(
            subject=subject,
            audience=self.audience,
            authenticated_at=authenticated_at,
            expires_at=expires_at,
        )


@dataclass(frozen=True, slots=True)
class DatabaseNotificationRecipientResolver:
    """Resolve one active user or Staff address on a dedicated directory connection."""

    sessions: sessionmaker[Session] = field(repr=False)
    ttl: timedelta = timedelta(seconds=20)

    def resolve(
        self,
        *,
        recipient_ref: str,
        channel: NotificationChannel,
        purpose: str,
        now: datetime,
    ) -> ResolvedRecipient:
        at = _aware(now)
        if purpose != "notification_delivery":
            raise NotificationDeliveryError("notification_recipient_purpose_invalid")
        kind, separator, raw_id = recipient_ref.partition(":")
        if not separator or kind not in {"user", "principal"}:
            raise NotificationDeliveryError("notification_recipient_invalid")
        try:
            recipient_id = UUID(raw_id)
        except ValueError as error:
            raise NotificationDeliveryError("notification_recipient_invalid") from error
        with self.sessions.begin() as db:
            _apply_notification_directory_recipient_rls(
                db, recipient_kind=kind, recipient_id=recipient_id
            )
            if kind == "user":
                column = (
                    GlobalUser.id if channel == "in_app" else GlobalUser.primary_email_normalized
                )
                value = db.execute(
                    sa.select(column).where(
                        GlobalUser.id == recipient_id,
                        GlobalUser.status == "active",
                    )
                ).scalar_one_or_none()
            elif kind == "principal":
                column = (
                    PlatformStaffPrincipalRecord.id
                    if channel == "in_app"
                    else PlatformStaffPrincipalRecord.email_normalized
                )
                value = db.execute(
                    sa.select(column).where(
                        PlatformStaffPrincipalRecord.id == recipient_id,
                        PlatformStaffPrincipalRecord.status == "active",
                    )
                ).scalar_one_or_none()
            else:  # pragma: no cover - kind is validated before opening the transaction.
                raise AssertionError("unreachable notification recipient kind")
        if value is None:
            raise NotificationDeliveryError("notification_recipient_address_invalid")
        if channel == "in_app":
            return ResolvedRecipient(
                address=f"in_app:{kind}:{recipient_id}",
                purpose=purpose,
                expires_at=at + self.ttl,
            )
        if not isinstance(value, str) or not _email_address(value):
            raise NotificationDeliveryError("notification_recipient_address_invalid")
        return ResolvedRecipient(
            address=value,
            purpose=purpose,
            expires_at=at + self.ttl,
        )


@dataclass(frozen=True, slots=True)
class EmptyNotificationRenderContextResolver:
    """Resolve the variable-free built-in catalog without persisting message content."""

    ttl: timedelta = timedelta(seconds=20)

    def resolve(
        self,
        *,
        delivery_id: UUID,
        event_type: str,
        expected_hmac: str,
        purpose: str,
        now: datetime,
    ) -> ResolvedRenderContext:
        del delivery_id, event_type
        if (
            purpose != "notification_render"
            or len(expected_hmac) != 64
            or any(value not in "0123456789abcdef" for value in expected_hmac)
        ):
            raise NotificationDeliveryError("notification_render_context_invalid")
        at = _aware(now)
        return ResolvedRenderContext(variables={}, purpose=purpose, expires_at=at + self.ttl)


@dataclass(frozen=True, slots=True)
class InAppNotificationProvider:
    """Acknowledge the durable delivery row as the in-app message itself."""

    digesters: dict[str, NotificationErrorDigester] = field(repr=False)

    def send(
        self,
        *,
        channel: NotificationChannel,
        address: str,
        subject: str,
        body: str,
        idempotency_key: str,
        hmac_key_id: str,
    ) -> DeliveryProviderReceipt:
        if channel != "in_app" or not address.startswith("in_app:"):
            raise NotificationDeliveryError("notification_provider_protocol_invalid")
        digester = _digester(self.digesters, hmac_key_id)
        request = digester.digest_values(
            domain="notification-in-app-request",
            values=(idempotency_key, address, subject, body),
        )
        receipt = digester.digest_values(
            domain="notification-in-app-receipt", values=(idempotency_key, request)
        )
        return DeliveryProviderReceipt(
            provider="in_app",
            provider_request_hmac=request,
            provider_receipt_hmac=receipt,
            provider_message_hmac=receipt,
        )


@dataclass(frozen=True, slots=True)
class HttpEmailNotificationProvider:
    """Send email through a bounded HTTPS JSON provider contract."""

    endpoint: str
    bearer_token: str = field(repr=False)
    digesters: dict[str, NotificationErrorDigester] = field(repr=False)
    client: httpx.Client = field(repr=False, compare=False)
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        try:
            endpoint = urlsplit(self.endpoint)
            port = endpoint.port
        except ValueError as error:
            raise ValueError("notification email provider configuration is invalid") from error
        if (
            len(self.endpoint) > 2048
            or endpoint.scheme != "https"
            or endpoint.hostname is None
            or endpoint.username is not None
            or endpoint.password is not None
            or bool(endpoint.query)
            or bool(endpoint.fragment)
            or any(character.isspace() for character in self.endpoint)
            or port not in {None, 443}
            or not self.bearer_token
            or not 0 < self.timeout_seconds <= 30
        ):
            raise ValueError("notification email provider configuration is invalid")

    def send(
        self,
        *,
        channel: NotificationChannel,
        address: str,
        subject: str,
        body: str,
        idempotency_key: str,
        hmac_key_id: str,
    ) -> DeliveryProviderReceipt:
        if channel != "email" or not _email_address(address):
            raise NotificationDeliveryError("notification_recipient_address_invalid")
        digester = _digester(self.digesters, hmac_key_id)
        payload = {
            "to": address,
            "subject": subject,
            "text": body,
            "idempotency_key": idempotency_key,
        }
        request_hmac = digester.digest_values(
            domain="notification-email-request",
            values=(address, subject, body, idempotency_key),
        )
        try:
            response = self.client.post(
                self.endpoint,
                headers={
                    "Authorization": f"Bearer {self.bearer_token}",
                    "Idempotency-Key": idempotency_key,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout_seconds,
                follow_redirects=False,
            )
        except httpx.HTTPError as error:
            raise NotificationDeliveryError(
                "notification_provider_unavailable", provider_status=503
            ) from error
        if not 200 <= response.status_code <= 299:
            code, _ = _provider_status(response.status_code)
            raise NotificationDeliveryError(code, provider_status=response.status_code)
        request_id = _provider_identifier(response.headers.get("X-Request-Id"))
        message_id = _provider_identifier(response.headers.get("X-Message-Id"))
        receipt_hmac = digester.digest_values(
            domain="notification-email-receipt",
            values=(idempotency_key, str(response.status_code), request_id),
        )
        message_hmac = digester.digest_values(
            domain="notification-email-message", values=(idempotency_key, message_id)
        )
        return DeliveryProviderReceipt(
            provider="https_email",
            provider_request_hmac=request_hmac,
            provider_receipt_hmac=receipt_hmac,
            provider_message_hmac=message_hmac,
        )


@dataclass(frozen=True, slots=True)
class CompositeNotificationProvider:
    in_app: InAppNotificationProvider
    email: HttpEmailNotificationProvider

    def send(
        self,
        *,
        channel: NotificationChannel,
        address: str,
        subject: str,
        body: str,
        idempotency_key: str,
        hmac_key_id: str,
    ) -> DeliveryProviderReceipt:
        values = {
            "channel": channel,
            "address": address,
            "subject": subject,
            "body": body,
            "idempotency_key": idempotency_key,
            "hmac_key_id": hmac_key_id,
        }
        if channel == "in_app":
            return self.in_app.send(**values)
        if channel == "email":
            return self.email.send(**values)
        raise NotificationDeliveryError("notification_channel_invalid")


@dataclass(frozen=True, slots=True)
class NotificationRuntimeComponents:
    authority: NotificationDeliveryService
    identity_provider: JwtNotificationWorkloadIdentityProvider
    recipient_resolver: DatabaseNotificationRecipientResolver
    context_resolver: EmptyNotificationRenderContextResolver
    catalog: NotificationTemplateCatalog
    provider: CompositeNotificationProvider


def build_default_notification_components(
    *,
    dispatcher_engine: Engine,
    directory_engine: Engine,
    dispatcher_sessions: sessionmaker[Session],
    directory_sessions: sessionmaker[Session],
    configuration: dict[str, str],
    http_client: httpx.Client | None = None,
) -> NotificationRuntimeComponents:
    verify_notification_dispatcher_database_role(dispatcher_engine)
    verify_notification_directory_database_role(directory_engine)
    current, previous = notification_digesters(configuration)
    digesters = {value.key_id: value for value in (current, *previous)}
    identity = JwtNotificationWorkloadIdentityProvider(
        token_file=Path(_required(configuration, "workload_token_file")),
        issuer=_required(configuration, "workload_issuer"),
        jwks_url=_required(configuration, "workload_jwks_url"),
    )
    email = HttpEmailNotificationProvider(
        endpoint=_required(configuration, "email_endpoint"),
        bearer_token=_required(configuration, "email_bearer_token"),
        digesters=digesters,
        client=http_client or httpx.Client(http2=True, trust_env=False, follow_redirects=False),
    )
    return NotificationRuntimeComponents(
        authority=NotificationDeliveryService(
            dispatcher_sessions,
            digester=current,
            previous_digesters=previous,
            dead_letter_sink=DeadLetterNotificationSink(
                DatabasePlatformNotificationAudience(directory_sessions)
            ),
        ),
        identity_provider=identity,
        recipient_resolver=DatabaseNotificationRecipientResolver(directory_sessions),
        context_resolver=EmptyNotificationRenderContextResolver(),
        catalog=PackagedNotificationTemplateCatalog(),
        provider=CompositeNotificationProvider(InAppNotificationProvider(digesters), email),
    )


def verify_notification_dispatcher_database_role(engine: Engine) -> None:
    """Fail startup unless the connection is the isolated dispatcher role."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production notification worker requires PostgreSQL")
    with engine.connect() as connection:
        facts = connection.execute(
            sa.text(
                "SELECT current_user, role.rolsuper, role.rolbypassrls, "
                "pg_has_role(current_user, 'saas_notification_dispatcher', 'member'), "
                "pg_has_role(current_user, 'saas_notification_scheduler', 'member'), "
                "pg_has_role(current_user, 'saas_platform_governance', 'member'), "
                "pg_has_role(current_user, 'saas_governance', 'member') "
                "FROM pg_roles role WHERE role.rolname = current_user"
            )
        ).one()
    if facts[1] or facts[2] or not facts[3] or any(facts[index] for index in (4, 5, 6)):
        raise RuntimeError("notification worker database role boundary is invalid")


def verify_notification_directory_database_role(engine: Engine) -> None:
    """Fail startup unless recipient lookup uses its isolated read-only role."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production notification directory requires PostgreSQL")
    with engine.connect() as connection:
        facts = connection.execute(
            sa.text(
                "SELECT current_user, role.rolsuper, role.rolbypassrls, "
                "pg_has_role(current_user, 'saas_notification_directory', 'member'), "
                "pg_has_role(current_user, 'saas_notification_dispatcher', 'member'), "
                "pg_has_role(current_user, 'saas_notification_scheduler', 'member'), "
                "pg_has_role(current_user, 'saas_platform_governance', 'member'), "
                "pg_has_role(current_user, 'saas_governance', 'member'), "
                "pg_has_role(current_user, 'saas_platform', 'member') "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
    if facts[1] or facts[2] or not facts[3] or any(facts[index] for index in (4, 5, 6, 7, 8)):
        raise RuntimeError("notification directory database role boundary is invalid")


def notification_digesters(
    configuration: dict[str, str],
) -> tuple[NotificationErrorDigester, tuple[NotificationErrorDigester, ...]]:
    current = NotificationErrorDigester(
        key_id=_required(configuration, "hmac_key_id"),
        secret=_secret(_required(configuration, "hmac_secret_b64")),
    )
    raw_previous = configuration.get("previous_hmac_keys_json", "[]")
    try:
        values = json.loads(raw_previous)
        previous = tuple(
            NotificationErrorDigester(
                key_id=str(value["key_id"]),
                secret=_secret(str(value["secret_b64"])),
            )
            for value in values
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("notification previous HMAC keys are invalid") from error
    return current, previous


def _secret(value: str) -> bytes:
    try:
        secret = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ValueError("notification HMAC secret is invalid") from error
    if len(secret) < 32:
        raise ValueError("notification HMAC secret is too short")
    return secret


def _required(values: dict[str, str], key: str) -> str:
    value = values.get(key, "").strip()
    if not value:
        raise ValueError(f"notification configuration {key} is required")
    return value


def _digester(
    values: dict[str, NotificationErrorDigester], key_id: str
) -> NotificationErrorDigester:
    value = values.get(key_id)
    if value is None:
        raise NotificationDeliveryError("notification_hmac_key_unavailable")
    return value


def _email_address(value: str) -> bool:
    return (
        3 <= len(value) <= 320
        and "@" in value
        and "\x00" not in value
        and not any(character.isspace() for character in value)
    )


def _provider_status(status: int) -> tuple[str, bool]:
    if status == 429:
        return "notification_provider_rate_limited", True
    if 500 <= status <= 599:
        return "notification_provider_unavailable", True
    if 400 <= status <= 499:
        return "notification_provider_rejected", False
    return "notification_provider_protocol_invalid", False


def _provider_identifier(value: str | None) -> str:
    if (
        value is None
        or not 1 <= len(value) <= 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise NotificationDeliveryError("notification_provider_protocol_invalid")
    return value


def _apply_notification_directory_recipient_rls(
    db: Session,
    *,
    recipient_kind: str,
    recipient_id: UUID,
) -> None:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    db.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_directory_recipient_kind', :kind, true), "
            "set_config('app.notification_directory_recipient_id', :recipient_id, true), "
            "set_config('app.notification_dead_letter_audience', '', true)"
        ),
        {"kind": recipient_kind, "recipient_id": str(recipient_id)},
    )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("notification runtime time must include a timezone")
    return value.astimezone(timezone.utc)


__all__ = [
    "CompositeNotificationProvider",
    "DatabaseNotificationRecipientResolver",
    "EmptyNotificationRenderContextResolver",
    "HttpEmailNotificationProvider",
    "InAppNotificationProvider",
    "JwtNotificationWorkloadIdentityProvider",
    "NotificationRuntimeComponents",
    "build_default_notification_components",
    "notification_digesters",
    "verify_notification_directory_database_role",
    "verify_notification_dispatcher_database_role",
]
