"""Content-blind notification rendering and lease-fenced delivery contracts."""

from __future__ import annotations

import hmac
import logging
import secrets
import string
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, Protocol
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import InstrumentedAttribute, Session, sessionmaker

from saas.control_plane.notification_models import (
    ApprovalWorkItemRecord,
    NotificationDeliveryAttemptRecord,
    NotificationDeliveryRecord,
    NotificationPreferenceRecord,
    NotificationTemplateRecord,
)

NotificationChannel = Literal["in_app", "email"]
DeliveryDisposition = Literal["succeeded", "retry", "dead_letter", "lease_lost", "suppressed"]

MAX_DELIVERY_ATTEMPTS = 8
RECIPIENT_RESOLUTION_PURPOSE = "notification_delivery"
PLATFORM_NOTIFICATION_READ_PERMISSION = "platform.notification.read"
PLATFORM_NOTIFICATION_REPLAY_PERMISSION = "platform.notification.replay"
PLATFORM_NOTIFICATION_TEMPLATE_MANAGE_PERMISSION = "platform.notification_template.manage"
_LOGGER = logging.getLogger("omnigent-saas-notification")
_LOCALE_FALLBACKS = {"en": "en-US", "zh": "zh-CN"}
_HEX_DIGITS = frozenset("0123456789abcdef")
_WORKLOAD_IDENTITY_MAX_AGE = timedelta(minutes=5)
_WORKLOAD_IDENTITY_MAX_TTL = timedelta(minutes=15)
_FAILURE_CODES = frozenset(
    {
        "notification_attempt_limit_exceeded",
        "notification_lease_expired",
        "notification_template_not_found",
        "notification_template_invalid",
        "notification_template_variable_not_allowlisted",
        "notification_template_variables_invalid",
        "notification_template_variables_missing",
        "notification_template_variable_invalid",
        "notification_template_field_invalid",
        "notification_template_render_failed",
        "notification_template_output_too_large",
        "notification_render_purpose_invalid",
        "notification_render_context_expired",
        "notification_recipient_purpose_invalid",
        "notification_recipient_resolution_expired",
        "notification_recipient_address_invalid",
        "notification_provider_rate_limited",
        "notification_provider_unavailable",
        "notification_provider_rejected",
        "notification_provider_protocol_invalid",
        "notification_provider_receipt_invalid",
    }
)


class NotificationDeliveryError(RuntimeError):
    """Stable delivery failure whose string form never exposes provider detail."""

    def __init__(self, code: str, *, provider_status: int | None = None) -> None:
        self.code = code
        self.provider_status = provider_status
        super().__init__(code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class NotificationTemplate:
    """Versioned template with an explicit variable allowlist."""

    key: str
    locale: str
    version: int
    subject: str = field(repr=False)
    body: str = field(repr=False)
    allowed_variables: frozenset[str]
    required_variables: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RenderedNotification:
    subject: str = field(repr=False)
    body: str = field(repr=False)
    template_key: str
    locale: str
    template_version: int


class NotificationTemplateCatalog(Protocol):
    """Resolve an immutable template version without recipient data."""

    def get(
        self,
        *,
        key: str,
        locale: str,
        version: int | None = None,
        artifact_handle: str | None = None,
        expected_content_sha256: str | None = None,
        expected_variables_schema_sha256: str | None = None,
    ) -> NotificationTemplate | None: ...


@dataclass(frozen=True, slots=True)
class ResolvedRecipient:
    """Short-lived address returned only for the requested delivery purpose."""

    address: str = field(repr=False)
    purpose: str
    expires_at: datetime


class RecipientAddressResolver(Protocol):
    """Resolve a purpose-bound opaque recipient reference just in time."""

    def resolve(
        self,
        *,
        recipient_ref: str,
        channel: NotificationChannel,
        purpose: str,
        now: datetime,
    ) -> ResolvedRecipient: ...


@dataclass(frozen=True, slots=True)
class ResolvedRenderContext:
    """Short-lived template values fetched by opaque delivery identity."""

    variables: dict[str, str] = field(repr=False)
    purpose: str
    expires_at: datetime


class NotificationRenderContextResolver(Protocol):
    """Resolve ephemeral variables; delivery rows contain only their digest."""

    def resolve(
        self,
        *,
        delivery_id: UUID,
        event_type: str,
        expected_hmac: str,
        purpose: str,
        now: datetime,
    ) -> ResolvedRenderContext: ...


@dataclass(frozen=True, slots=True)
class NotificationErrorDigester:
    """Domain-separated keyed fingerprint for stable failure classification."""

    key_id: str
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not self.key_id.strip() or len(self.secret) < 32:
            raise ValueError("notification error digester requires a 256-bit key")

    def digest(self, *, domain: str, error_code: str, provider_status: int | None) -> str:
        if not domain.strip() or not error_code.strip():
            raise ValueError("notification error digest inputs are required")
        material = f"omnigent:{domain}:v1\x00{error_code}\x00{provider_status or 0}"
        return hmac.new(self.secret, material.encode("utf-8"), sha256).hexdigest()

    def digest_values(self, *, domain: str, values: tuple[str, ...]) -> str:
        if not domain.strip() or not values:
            raise ValueError("notification digest inputs are required")
        material = "\x00".join((f"omnigent:{domain}:v1", *values))
        return hmac.new(self.secret, material.encode("utf-8"), sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class DeliveryProviderReceipt:
    """Non-sensitive provider acknowledgement."""

    provider: str
    provider_request_hmac: str
    provider_receipt_hmac: str
    provider_message_hmac: str


class NotificationProvider(Protocol):
    """Perform one idempotent network send outside a database transaction."""

    def send(
        self,
        *,
        channel: NotificationChannel,
        address: str,
        subject: str,
        body: str,
        idempotency_key: str,
        hmac_key_id: str,
    ) -> DeliveryProviderReceipt: ...


@dataclass(frozen=True, slots=True)
class ClaimedNotificationDelivery:
    delivery_id: UUID
    message_id: UUID
    tenant_id: UUID | None
    realm: str
    recipient_id: UUID
    channel: NotificationChannel
    template_id: UUID
    approval_work_item_id: UUID | None
    operation_batch_id: UUID | None
    source_delivery_id: UUID | None
    hmac_key_id: str
    recipient_ref: str
    template_key: str
    locale: str
    template_version: int
    template_artifact_handle: str
    template_content_sha256: str
    template_variables_schema_sha256: str
    event_type: str
    render_context_hmac: str
    attempt_number: int
    lease_generation: int
    lease_token: str
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class NotificationWorkloadIdentity:
    subject: str = field(repr=False)
    audience: str
    authenticated_at: datetime
    expires_at: datetime


class NotificationWorkloadIdentityProvider(Protocol):
    def identity(self, *, now: datetime) -> NotificationWorkloadIdentity: ...


@dataclass(frozen=True, slots=True)
class DeliverySettlement:
    delivery_id: UUID
    status: DeliveryDisposition
    attempt_number: int
    available_at: datetime | None = None


class NotificationDeliveryAuthority(Protocol):
    """Database authority; each method owns one short transaction."""

    def claim(
        self, identity: NotificationWorkloadIdentity, *, now: datetime
    ) -> ClaimedNotificationDelivery | None: ...

    def ensure_sendable(
        self,
        claim: ClaimedNotificationDelivery,
        *,
        now: datetime,
    ) -> DeliverySettlement | None: ...

    def complete(
        self,
        claim: ClaimedNotificationDelivery,
        *,
        receipt: DeliveryProviderReceipt,
        now: datetime,
    ) -> DeliverySettlement: ...

    def fail(
        self,
        claim: ClaimedNotificationDelivery,
        *,
        error_code: str,
        provider_status: int | None,
        retryable: bool,
        now: datetime,
    ) -> DeliverySettlement: ...


class NotificationDeadLetterSink(Protocol):
    """Emit one platform alert in the same delivery-settlement transaction."""

    def enqueue_dead_letter_in_transaction(
        self,
        deliveries: NotificationDeliveryService,
        db: Session,
        *,
        tenant_id: UUID | None,
        delivery_id: UUID,
        replay_generation: int,
        now: datetime,
    ) -> None: ...


def normalize_locale(locale: str) -> str:
    """Normalize a bounded locale and preserve deterministic English fallback."""

    cleaned = locale.strip().replace("_", "-")
    if not cleaned or len(cleaned) > 35:
        return "en-US"
    language = cleaned.split("-", 1)[0].lower()
    return _LOCALE_FALLBACKS.get(language, cleaned)


def render_notification(
    catalog: NotificationTemplateCatalog,
    *,
    template_key: str,
    locale: str,
    variables: dict[str, str],
    template_version: int | None = None,
    artifact_handle: str | None = None,
    expected_content_sha256: str | None = None,
    expected_variables_schema_sha256: str | None = None,
) -> RenderedNotification:
    """Render only allowlisted scalar variables with locale fallback."""

    normalized = normalize_locale(locale)
    template = catalog.get(
        key=template_key,
        locale=normalized,
        version=template_version,
        artifact_handle=artifact_handle,
        expected_content_sha256=expected_content_sha256,
        expected_variables_schema_sha256=expected_variables_schema_sha256,
    )
    if template is None and normalized != "en-US":
        template = catalog.get(
            key=template_key,
            locale="en-US",
            version=template_version,
            artifact_handle=artifact_handle,
            expected_content_sha256=expected_content_sha256,
            expected_variables_schema_sha256=expected_variables_schema_sha256,
        )
    if template is None:
        raise NotificationDeliveryError("notification_template_not_found")
    if (
        template.version < 1
        or template.key != template_key
        or (template_version is not None and template.version != template_version)
    ):
        raise NotificationDeliveryError("notification_template_invalid")
    fields = _template_fields(template.subject) | _template_fields(template.body)
    if not fields <= template.allowed_variables:
        raise NotificationDeliveryError("notification_template_variable_not_allowlisted")
    provided = set(variables)
    if not template.required_variables <= provided or not provided <= template.allowed_variables:
        raise NotificationDeliveryError("notification_template_variables_invalid")
    if fields - provided:
        raise NotificationDeliveryError("notification_template_variables_missing")
    normalized_values: dict[str, str] = {}
    for key, value in variables.items():
        if not isinstance(value, str) or len(value) > 512 or "\x00" in value:
            raise NotificationDeliveryError("notification_template_variable_invalid")
        normalized_values[key] = value
    try:
        subject = template.subject.format_map(normalized_values)
        body = template.body.format_map(normalized_values)
    except (KeyError, ValueError) as error:
        raise NotificationDeliveryError("notification_template_render_failed") from error
    if len(subject) > 998 or len(body) > 100_000:
        raise NotificationDeliveryError("notification_template_output_too_large")
    return RenderedNotification(
        subject=subject,
        body=body,
        template_key=template.key,
        locale=template.locale,
        template_version=template.version,
    )


def classify_provider_status(status_code: int) -> tuple[str, bool]:
    """Map HTTP-like provider status to stable retry policy."""

    if status_code == 429:
        return "notification_provider_rate_limited", True
    if 500 <= status_code <= 599:
        return "notification_provider_unavailable", True
    if 400 <= status_code <= 499:
        return "notification_provider_rejected", False
    return "notification_provider_protocol_invalid", False


class NotificationDeliveryWorker:
    """Claim, resolve, render, and send without holding a transaction over I/O."""

    def __init__(
        self,
        authority: NotificationDeliveryAuthority,
        identity_provider: NotificationWorkloadIdentityProvider,
        resolver: RecipientAddressResolver,
        context_resolver: NotificationRenderContextResolver,
        catalog: NotificationTemplateCatalog,
        provider: NotificationProvider,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._authority = authority
        self._identity_provider = identity_provider
        self._resolver = resolver
        self._context_resolver = context_resolver
        self._catalog = catalog
        self._provider = provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._clock_was_supplied = clock is not None

    def deliver_once(self, *, now: datetime | None = None) -> DeliverySettlement | None:
        delivered_at = _aware(now or datetime.now(timezone.utc))
        phase_clock = (
            self._clock if self._clock_was_supplied or now is None else lambda: delivered_at
        )
        identity = self._identity_provider.identity(now=delivered_at)
        _validate_workload_identity(identity, delivered_at)
        claim = self._authority.claim(identity, now=delivered_at)
        if claim is None:
            return None
        try:
            if claim.attempt_number < 1 or claim.attempt_number > MAX_DELIVERY_ATTEMPTS:
                raise NotificationDeliveryError("notification_attempt_limit_exceeded")
            if _aware(claim.lease_expires_at) <= delivered_at:
                raise NotificationDeliveryError("notification_lease_expired")
            context_at = _aware(phase_clock())
            context = self._context_resolver.resolve(
                delivery_id=claim.delivery_id,
                event_type=claim.event_type,
                expected_hmac=claim.render_context_hmac,
                purpose="notification_render",
                now=context_at,
            )
            if context.purpose != "notification_render":
                raise NotificationDeliveryError("notification_render_purpose_invalid")
            if _aware(context.expires_at) <= context_at:
                raise NotificationDeliveryError("notification_render_context_expired")
            rendered = render_notification(
                self._catalog,
                template_key=claim.template_key,
                locale=claim.locale,
                variables=context.variables,
                template_version=claim.template_version,
                artifact_handle=claim.template_artifact_handle,
                expected_content_sha256=claim.template_content_sha256,
                expected_variables_schema_sha256=(claim.template_variables_schema_sha256),
            )
            recipient_at = _aware(phase_clock())
            recipient = self._resolver.resolve(
                recipient_ref=claim.recipient_ref,
                channel=claim.channel,
                purpose=RECIPIENT_RESOLUTION_PURPOSE,
                now=recipient_at,
            )
            if recipient.purpose != RECIPIENT_RESOLUTION_PURPOSE:
                raise NotificationDeliveryError("notification_recipient_purpose_invalid")
            if _aware(recipient.expires_at) <= recipient_at:
                raise NotificationDeliveryError("notification_recipient_resolution_expired")
            if not recipient.address or len(recipient.address) > 2048:
                raise NotificationDeliveryError("notification_recipient_address_invalid")
            suppressed = self._authority.ensure_sendable(claim, now=_aware(phase_clock()))
            if suppressed is not None:
                return suppressed
            receipt = self._provider.send(
                channel=claim.channel,
                address=recipient.address,
                subject=rendered.subject,
                body=rendered.body,
                idempotency_key=str(claim.delivery_id),
                hmac_key_id=claim.hmac_key_id,
            )
            _validate_provider_receipt(receipt)
        except NotificationDeliveryError as error:
            retryable = error.provider_status == 429 or (
                error.provider_status is not None and error.provider_status >= 500
            )
            return self._settle_failure(
                claim,
                error.code,
                error.provider_status,
                retryable,
                _aware(phase_clock()),
            )
        except Exception as error:  # noqa: BLE001 - provider exceptions are content-blind retries
            status = getattr(error, "status_code", None)
            if isinstance(status, int):
                code, retryable = classify_provider_status(status)
            else:
                code, retryable = "notification_provider_unavailable", True
            return self._settle_failure(claim, code, status, retryable, _aware(phase_clock()))
        try:
            return self._authority.complete(claim, receipt=receipt, now=_aware(phase_clock()))
        except NotificationDeliveryError as error:
            if error.code != "notification_delivery_lease_lost":
                raise
            return DeliverySettlement(
                delivery_id=claim.delivery_id,
                status="lease_lost",
                attempt_number=claim.attempt_number,
            )

    def _settle_failure(
        self,
        claim: ClaimedNotificationDelivery,
        code: str,
        provider_status: int | None,
        retryable: bool,
        at: datetime,
    ) -> DeliverySettlement:
        retry = retryable and claim.attempt_number < MAX_DELIVERY_ATTEMPTS
        _LOGGER.warning(
            "notification delivery failed",
            extra={
                "delivery_id": str(claim.delivery_id),
                "error_code": code,
                "retryable": retry,
            },
        )
        try:
            return self._authority.fail(
                claim,
                error_code=code,
                provider_status=provider_status,
                retryable=retryable,
                now=at,
            )
        except NotificationDeliveryError as error:
            if error.code != "notification_delivery_lease_lost":
                raise
            return DeliverySettlement(
                delivery_id=claim.delivery_id,
                status="lease_lost",
                attempt_number=claim.attempt_number,
            )


def _template_fields(value: str) -> set[str]:
    fields: set[str] = set()
    try:
        parsed = string.Formatter().parse(value)
        for _, field_name, _, _ in parsed:
            if field_name is None:
                continue
            if not field_name.isidentifier():
                raise NotificationDeliveryError("notification_template_field_invalid")
            fields.add(field_name)
    except ValueError as error:
        raise NotificationDeliveryError("notification_template_invalid") from error
    return fields


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("notification time must include a timezone")
    return value.astimezone(timezone.utc)


NOTIFICATION_EVENT_TYPES = frozenset(
    {
        "approval.requested",
        "approval.reminder",
        "approval.escalated",
        "approval.expired",
        "approval.decided",
        "approval.decision_failed",
        "operation_batch.completed",
        "notification.delivery_dead_letter",
        "privacy.retention_attention_required",
    }
)
MANDATORY_NOTIFICATION_EVENTS = frozenset(
    {
        "approval.escalated",
        "approval.expired",
        "approval.decision_failed",
        "notification.delivery_dead_letter",
        "privacy.retention_attention_required",
    }
)


@dataclass(frozen=True, slots=True)
class NotificationActor:
    realm: Literal["tenant", "staff"]
    actor_id: UUID
    tenant_id: UUID | None
    permissions: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class NotificationEnqueueCommand:
    realm: Literal["tenant", "staff"]
    tenant_id: UUID | None
    recipient_id: UUID
    event_type: str
    template_key: str
    channels: tuple[NotificationChannel, ...]
    template_ids: dict[NotificationChannel, UUID]
    deduplication_token: str = field(repr=False)
    render_context_values: tuple[str, ...] = field(repr=False)
    approval_work_item_id: UUID | None = None
    operation_batch_id: UUID | None = None
    source_delivery_id: UUID | None = None
    forced: bool = False
    locale: str = "en-US"


@dataclass(frozen=True, slots=True)
class NotificationEventCommand:
    """Transaction-local event whose immutable templates are DB-selected."""

    realm: Literal["tenant", "staff"]
    tenant_id: UUID | None
    recipient_id: UUID
    event_type: str
    channels: tuple[NotificationChannel, ...]
    deduplication_token: str = field(repr=False)
    render_context_values: tuple[str, ...] = field(repr=False)
    approval_work_item_id: UUID | None = None
    operation_batch_id: UUID | None = None
    source_delivery_id: UUID | None = None
    forced: bool = False
    locale: str = "en-US"


@dataclass(frozen=True, slots=True)
class NotificationDeliveryView:
    id: UUID
    realm: str
    tenant_id: UUID | None
    event_type: str
    channel: str
    approval_work_item_id: UUID | None
    operation_batch_id: UUID | None
    source_delivery_id: UUID | None
    status: str
    attempt_count: int
    max_attempts: int
    replay_generation: int
    available_at: datetime
    delivered_at: datetime | None
    recipient_read_at: datetime | None
    suppression_code: str | None
    inflight_boundary_code: str | None
    last_error_code: str | None
    version: int


@dataclass(frozen=True, slots=True)
class NotificationDeliveryPage:
    items: tuple[NotificationDeliveryView, ...]
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class NotificationPreferenceView:
    id: UUID
    event_type: str
    channel: str
    enabled: bool
    locale: str
    version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class NotificationTemplateView:
    id: UUID
    realm: str
    tenant_id: UUID | None
    template_key: str
    channel: str
    locale: str
    version: int
    content_artifact_handle: str
    content_sha256: str
    variables_schema_sha256: str
    status: str
    replayed: bool = False


class NotificationDeliveryService(NotificationDeliveryAuthority):
    """Persistent content-blind queue and recipient preference authority."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        digester: NotificationErrorDigester,
        previous_digesters: tuple[NotificationErrorDigester, ...] = (),
        dead_letter_sink: NotificationDeadLetterSink | None = None,
    ) -> None:
        self._sessions = session_factory
        self._digester = digester
        self._digesters = (digester, *previous_digesters)
        if len({value.key_id for value in self._digesters}) != len(self._digesters):
            raise ValueError("notification HMAC key IDs must be unique")
        self._dead_letter_sink = dead_letter_sink

    def enqueue_event_in_transaction(
        self,
        db: Session,
        command: NotificationEventCommand,
        *,
        now: datetime | None = None,
    ) -> tuple[NotificationDeliveryView, ...]:
        """Select exact Staff-owned templates and enqueue in the caller transaction."""

        _notification_scope(command.realm, command.tenant_id)
        if not command.channels or len(set(command.channels)) != len(command.channels):
            raise NotificationDeliveryError("notification_channels_invalid")
        if any(value not in {"in_app", "email"} for value in command.channels):
            raise NotificationDeliveryError("notification_channel_invalid")
        event_type = _event_type(command.event_type)
        locale = normalize_locale(command.locale)
        _apply_notification_delivery_rls(
            db,
            realm=command.realm,
            tenant_id=command.tenant_id,
            actor=NotificationActor(
                realm=command.realm,
                actor_id=command.recipient_id,
                tenant_id=command.tenant_id,
            ),
            work_item_id=command.approval_work_item_id,
            batch_id=command.operation_batch_id,
            source_delivery_id=command.source_delivery_id,
            event_type=event_type,
            channels=command.channels,
            locale=locale,
            mutation="enqueue_template_resolve",
        )
        template_ids = self._active_template_ids(
            db,
            tenant_id=command.tenant_id,
            event_type=event_type,
            locale=locale,
            channels=command.channels,
        )
        return self.enqueue_in_transaction(
            db,
            NotificationEnqueueCommand(
                realm=command.realm,
                tenant_id=command.tenant_id,
                recipient_id=command.recipient_id,
                event_type=event_type,
                template_key=event_type,
                channels=command.channels,
                template_ids=template_ids,
                deduplication_token=command.deduplication_token,
                render_context_values=command.render_context_values,
                approval_work_item_id=command.approval_work_item_id,
                operation_batch_id=command.operation_batch_id,
                source_delivery_id=command.source_delivery_id,
                forced=command.forced,
                locale=locale,
            ),
            now=now,
        )

    def enqueue_in_transaction(
        self,
        db: Session,
        command: NotificationEnqueueCommand,
        *,
        now: datetime | None = None,
    ) -> tuple[NotificationDeliveryView, ...]:
        queued_at = _aware(now or datetime.now(timezone.utc))
        _notification_scope(command.realm, command.tenant_id)
        event_type = _event_type(command.event_type)
        if (event_type == "notification.delivery_dead_letter") is not (
            command.source_delivery_id is not None
        ):
            raise NotificationDeliveryError("notification_dead_letter_source_invalid")
        template_key = _bounded(command.template_key, "template_key", 128)
        token = _bounded(command.deduplication_token, "deduplication_token", 512)
        if not command.channels or len(set(command.channels)) != len(command.channels):
            raise NotificationDeliveryError("notification_channels_invalid")
        if any(value not in {"in_app", "email"} for value in command.channels):
            raise NotificationDeliveryError("notification_channel_invalid")
        context_hmac = self._digester.digest_values(
            domain="notification-render-context",
            values=(event_type, *command.render_context_values),
        )
        views: list[NotificationDeliveryView] = []
        for channel in command.channels:
            template_id = command.template_ids.get(channel)
            if template_id is None:
                raise NotificationDeliveryError("notification_template_id_required")
            dedupe_values = (
                command.realm,
                str(command.tenant_id or "platform"),
                str(command.recipient_id),
                event_type,
                channel,
                token,
                str(command.source_delivery_id or "none"),
            )
            candidates = tuple(
                (
                    value,
                    value.digest_values(domain="notification-deduplication", values=dedupe_values),
                )
                for value in self._digesters
            )
            existing = None
            for candidate_digester, candidate_hmac in candidates:
                candidate_id = UUID(hex=candidate_hmac[:32])
                _apply_notification_delivery_rls(
                    db,
                    realm=command.realm,
                    tenant_id=command.tenant_id,
                    actor=NotificationActor(
                        realm=command.realm,
                        actor_id=command.recipient_id,
                        tenant_id=command.tenant_id,
                    ),
                    delivery_id=candidate_id,
                    template_id=template_id,
                    work_item_id=command.approval_work_item_id,
                    batch_id=command.operation_batch_id,
                    source_delivery_id=command.source_delivery_id,
                    event_type=event_type,
                    channels=(channel,),
                    locale=normalize_locale(command.locale),
                    mutation="enqueue",
                )
                candidate_record = db.get(NotificationDeliveryRecord, candidate_id)
                if candidate_record is not None:
                    if candidate_record.hmac_key_id != candidate_digester.key_id:
                        raise NotificationDeliveryError("notification_deduplication_key_mismatch")
                    existing = candidate_record
                    break
            if existing is not None:
                views.append(_delivery_view(existing))
                continue
            deduplication_key = candidates[0][1]
            delivery_id = UUID(hex=deduplication_key[:32])
            _apply_notification_delivery_rls(
                db,
                realm=command.realm,
                tenant_id=command.tenant_id,
                actor=NotificationActor(
                    realm=command.realm,
                    actor_id=command.recipient_id,
                    tenant_id=command.tenant_id,
                ),
                delivery_id=delivery_id,
                template_id=template_id,
                work_item_id=command.approval_work_item_id,
                batch_id=command.operation_batch_id,
                source_delivery_id=command.source_delivery_id,
                event_type=event_type,
                channels=(channel,),
                locale=normalize_locale(command.locale),
                mutation="enqueue",
            )
            preference = self._preference(
                db,
                realm=command.realm,
                tenant_id=command.tenant_id,
                recipient_id=command.recipient_id,
                event_type=event_type,
                channel=channel,
            )
            locale = normalize_locale(preference.locale if preference else command.locale)
            _apply_notification_delivery_rls(
                db,
                realm=command.realm,
                tenant_id=command.tenant_id,
                actor=NotificationActor(
                    realm=command.realm,
                    actor_id=command.recipient_id,
                    tenant_id=command.tenant_id,
                ),
                delivery_id=delivery_id,
                template_id=template_id,
                work_item_id=command.approval_work_item_id,
                batch_id=command.operation_batch_id,
                source_delivery_id=command.source_delivery_id,
                event_type=event_type,
                channels=(channel,),
                locale=locale,
                mutation="enqueue",
            )
            template = self._template(
                db,
                template_id=template_id,
                tenant_id=command.tenant_id,
                template_key=template_key,
                channel=channel,
                locale=locale,
            )
            enabled = (
                command.forced
                or event_type in MANDATORY_NOTIFICATION_EVENTS
                or preference is None
                or preference.enabled
            )
            record = NotificationDeliveryRecord(
                id=delivery_id,
                realm=command.realm,
                tenant_id=command.tenant_id,
                recipient_user_id=(command.recipient_id if command.realm == "tenant" else None),
                recipient_principal_id=(
                    command.recipient_id if command.realm == "staff" else None
                ),
                event_type=event_type,
                channel=channel,
                template_id=template.id,
                approval_work_item_id=command.approval_work_item_id,
                operation_batch_id=command.operation_batch_id,
                source_delivery_id=command.source_delivery_id,
                deduplication_key=deduplication_key,
                recipient_locator_hmac=self._digester.digest_values(
                    domain="notification-recipient-locator",
                    values=(command.realm, str(command.recipient_id)),
                ),
                render_context_hmac=context_hmac,
                hmac_key_id=self._digester.key_id,
                status="pending" if enabled else "suppressed",
                attempt_count=0,
                max_attempts=MAX_DELIVERY_ATTEMPTS,
                replay_generation=0,
                available_at=queued_at,
                lease_generation=0,
                suppression_code=None if enabled else "preference_disabled",
                version=1,
                created_at=queued_at,
                updated_at=queued_at,
            )
            db.add(record)
            db.flush()
            views.append(_delivery_view(record))
        return tuple(views)

    def list_deliveries(
        self,
        actor: NotificationActor,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: UUID | None = None,
        now: datetime | None = None,
    ) -> NotificationDeliveryPage:
        del now
        _notification_scope(actor.realm, actor.tenant_id)
        if not 1 <= limit <= 100:
            raise NotificationDeliveryError("notification_page_limit_invalid")
        if status is not None and status not in {
            "pending",
            "leased",
            "retry",
            "succeeded",
            "dead_letter",
            "suppressed",
        }:
            raise NotificationDeliveryError("notification_status_invalid")
        platform_dlq = (
            actor.realm == "staff"
            and actor.tenant_id is None
            and status == "dead_letter"
            and PLATFORM_NOTIFICATION_READ_PERMISSION in getattr(actor, "permissions", frozenset())
        )
        with self._sessions.begin() as db:
            _apply_notification_delivery_rls(
                db,
                realm=actor.realm,
                tenant_id=actor.tenant_id,
                actor=actor,
            )
            recipient = (
                NotificationDeliveryRecord.recipient_user_id == actor.actor_id
                if actor.realm == "tenant"
                else NotificationDeliveryRecord.recipient_principal_id == actor.actor_id
            )
            query = sa.select(NotificationDeliveryRecord)
            if not platform_dlq:
                query = query.where(
                    NotificationDeliveryRecord.realm == actor.realm,
                    recipient,
                )
            if not platform_dlq and (actor.realm == "tenant" or actor.tenant_id is not None):
                query = query.where(NotificationDeliveryRecord.tenant_id == actor.tenant_id)
            if status is not None:
                query = query.where(NotificationDeliveryRecord.status == status)
            if cursor is not None:
                query = query.where(NotificationDeliveryRecord.id > cursor)
            values = tuple(
                db.execute(
                    query.order_by(NotificationDeliveryRecord.id).limit(limit + 1)
                ).scalars()
            )
            items = tuple(_delivery_view(value) for value in values[:limit])
        return NotificationDeliveryPage(
            items=items,
            next_cursor=(items[-1].id if len(values) > limit and items else None),
        )

    def replay(
        self,
        actor: NotificationActor,
        *,
        delivery_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> NotificationDeliveryView:
        replayed_at = _aware(now or datetime.now(timezone.utc))
        key = _bounded(idempotency_key, "idempotency_key", 128)
        with self._sessions.begin() as db:
            platform_replay = (
                actor.realm == "staff"
                and actor.tenant_id is None
                and PLATFORM_NOTIFICATION_REPLAY_PERMISSION
                in getattr(actor, "permissions", frozenset())
            )
            _apply_notification_delivery_rls(
                db,
                realm=actor.realm,
                tenant_id=actor.tenant_id,
                actor=actor,
                delivery_id=delivery_id,
                mutation="read" if platform_replay else "replay",
            )
            candidate = db.execute(
                sa.select(NotificationDeliveryRecord).where(
                    NotificationDeliveryRecord.id == delivery_id
                )
            ).scalar_one_or_none()
            if candidate is None:
                raise NotificationDeliveryError("notification_delivery_not_found")
            cross_recipient = not _delivery_visible(candidate, actor)
            if cross_recipient and (not platform_replay or candidate.status != "dead_letter"):
                raise NotificationDeliveryError("notification_delivery_not_found")
            _apply_notification_delivery_rls(
                db,
                realm=candidate.realm,
                tenant_id=candidate.tenant_id,
                actor=actor,
                delivery_id=delivery_id,
                template_id=candidate.template_id,
                work_item_id=candidate.approval_work_item_id,
                batch_id=candidate.operation_batch_id,
                mutation="replay",
            )
            record = db.execute(
                sa.select(NotificationDeliveryRecord)
                .where(NotificationDeliveryRecord.id == delivery_id)
                .with_for_update()
            ).scalar_one_or_none()
            if record is None or (not _delivery_visible(record, actor) and not platform_replay):
                raise NotificationDeliveryError("notification_delivery_not_found")
            digester = self._digester_for_key(record.hmac_key_id)
            key_hmac = digester.digest_values(
                domain="notification-replay-idempotency",
                values=(str(record.id), key),
            )
            request_hmac = digester.digest_values(
                domain="notification-replay-request",
                values=(str(record.id), str(expected_version)),
            )
            if record.replay_idempotency_hmac is not None:
                if hmac.compare_digest(record.replay_idempotency_hmac, key_hmac):
                    if not hmac.compare_digest(record.replay_request_hmac or "", request_hmac):
                        raise NotificationDeliveryError("notification_replay_payload_conflict")
                    return _delivery_view(record)
                if record.status != "dead_letter":
                    raise NotificationDeliveryError("notification_replay_idempotency_conflict")
            if record.status != "dead_letter" or record.version != expected_version:
                raise NotificationDeliveryError("notification_replay_conflict")
            record.status = "pending"
            record.attempt_count = 0
            record.available_at = replayed_at
            record.last_error_code = None
            record.last_error_hmac = None
            record.replay_generation += 1
            record.replay_receipt_generation = record.replay_generation
            record.replay_idempotency_hmac = key_hmac
            record.replay_request_hmac = request_hmac
            record.version += 1
            record.updated_at = replayed_at
            db.flush()
            return _delivery_view(record)

    def mark_read(
        self,
        actor: NotificationActor,
        *,
        delivery_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> NotificationDeliveryView:
        read_at = _aware(now or datetime.now(timezone.utc))
        key = _bounded(idempotency_key, "idempotency_key", 128)
        with self._sessions.begin() as db:
            _apply_notification_delivery_rls(
                db,
                realm=actor.realm,
                tenant_id=actor.tenant_id,
                actor=actor,
                delivery_id=delivery_id,
                mutation="ack",
            )
            record = db.execute(
                sa.select(NotificationDeliveryRecord)
                .where(NotificationDeliveryRecord.id == delivery_id)
                .with_for_update()
            ).scalar_one_or_none()
            if record is None or not _delivery_visible(record, actor):
                raise NotificationDeliveryError("notification_delivery_not_found")
            digester = self._digester_for_key(record.hmac_key_id)
            key_hmac = digester.digest_values(
                domain="notification-read-idempotency", values=(str(record.id), key)
            )
            request_hmac = digester.digest_values(
                domain="notification-read-request",
                values=(str(record.id), str(expected_version)),
            )
            if record.read_idempotency_hmac is not None:
                if not hmac.compare_digest(record.read_idempotency_hmac, key_hmac):
                    raise NotificationDeliveryError("notification_read_idempotency_conflict")
                if not hmac.compare_digest(record.read_request_hmac or "", request_hmac):
                    raise NotificationDeliveryError("notification_read_payload_conflict")
                return _delivery_view(record)
            if (
                record.channel != "in_app"
                or record.status != "succeeded"
                or record.version != expected_version
            ):
                raise NotificationDeliveryError("notification_read_conflict")
            record.recipient_read_at = read_at
            record.read_idempotency_hmac = key_hmac
            record.read_request_hmac = request_hmac
            record.version += 1
            record.updated_at = read_at
            db.flush()
            return _delivery_view(record)

    def list_preferences(
        self,
        actor: NotificationActor,
        *,
        now: datetime | None = None,
    ) -> tuple[NotificationPreferenceView, ...]:
        del now
        with self._sessions.begin() as db:
            _apply_notification_delivery_rls(
                db,
                realm=actor.realm,
                tenant_id=actor.tenant_id,
                actor=actor,
                mutation="preference_list",
            )
            recipient = (
                NotificationPreferenceRecord.recipient_user_id == actor.actor_id
                if actor.realm == "tenant"
                else NotificationPreferenceRecord.recipient_principal_id == actor.actor_id
            )
            query = sa.select(NotificationPreferenceRecord).where(
                NotificationPreferenceRecord.realm == actor.realm,
                recipient,
            )
            if actor.realm == "tenant" or actor.tenant_id is not None:
                query = query.where(NotificationPreferenceRecord.tenant_id == actor.tenant_id)
            values = tuple(
                db.execute(
                    query.order_by(
                        NotificationPreferenceRecord.event_type,
                        NotificationPreferenceRecord.channel,
                    )
                ).scalars()
            )
            return tuple(_preference_view(value, replayed=False) for value in values)

    def update_preference(
        self,
        actor: NotificationActor,
        *,
        preference_id: UUID,
        expected_version: int,
        enabled: bool,
        locale: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> NotificationPreferenceView:
        updated_at = _aware(now or datetime.now(timezone.utc))
        normalized_locale = normalize_locale(locale)
        key = _bounded(idempotency_key, "idempotency_key", 128)
        with self._sessions.begin() as db:
            _apply_notification_delivery_rls(
                db,
                realm=actor.realm,
                tenant_id=actor.tenant_id,
                actor=actor,
                mutation="preference",
            )
            record = db.execute(
                sa.select(NotificationPreferenceRecord)
                .where(NotificationPreferenceRecord.id == preference_id)
                .with_for_update()
            ).scalar_one_or_none()
            if record is None or not _preference_visible(record, actor):
                raise NotificationDeliveryError("notification_preference_not_found")
            event, channel = record.event_type, record.channel
            for candidate in self._digesters:
                candidate_key = candidate.digest_values(
                    domain="notification-preference-idempotency",
                    values=(actor.realm, str(actor.actor_id), event, channel, key),
                )
                if hmac.compare_digest(record.idempotency_key_hmac, candidate_key):
                    candidate_request = candidate.digest_values(
                        domain="notification-preference-request",
                        values=(
                            event,
                            channel,
                            str(enabled),
                            normalized_locale,
                            str(expected_version),
                        ),
                    )
                    if candidate.key_id != record.hmac_key_id or not hmac.compare_digest(
                        record.request_hmac, candidate_request
                    ):
                        raise NotificationDeliveryError(
                            "notification_preference_idempotency_conflict"
                        )
                    return _preference_view(record, replayed=True)
            key_hmac = self._digester.digest_values(
                domain="notification-preference-idempotency",
                values=(actor.realm, str(actor.actor_id), event, channel, key),
            )
            request_hmac = self._digester.digest_values(
                domain="notification-preference-request",
                values=(
                    event,
                    channel,
                    str(enabled),
                    normalized_locale,
                    str(expected_version),
                ),
            )
            if record.version != expected_version:
                raise NotificationDeliveryError("notification_preference_conflict")
            record.enabled = enabled
            record.locale = normalized_locale
            record.idempotency_key_hmac = key_hmac
            record.request_hmac = request_hmac
            record.hmac_key_id = self._digester.key_id
            record.version += 1
            record.updated_at = updated_at
            db.flush()
            return _preference_view(record, replayed=False)

    def list_templates(
        self,
        actor: NotificationActor,
        *,
        now: datetime | None = None,
    ) -> tuple[NotificationTemplateView, ...]:
        del now
        _notification_scope(actor.realm, actor.tenant_id)
        if actor.realm == "staff":
            _require_platform_permission(actor, PLATFORM_NOTIFICATION_READ_PERMISSION)
        with self._sessions.begin() as db:
            _apply_notification_delivery_rls(
                db,
                realm="staff",
                tenant_id=actor.tenant_id,
                actor=actor,
                mutation="template_list",
            )
            query = sa.select(NotificationTemplateRecord).where(
                NotificationTemplateRecord.realm == "staff"
            )
            if actor.realm == "tenant":
                query = query.where(
                    _tenant_or_global(NotificationTemplateRecord.tenant_id, actor.tenant_id),
                    NotificationTemplateRecord.status == "active",
                )
            values = tuple(
                db.execute(
                    query.order_by(
                        NotificationTemplateRecord.tenant_id,
                        NotificationTemplateRecord.template_key,
                        NotificationTemplateRecord.channel,
                        NotificationTemplateRecord.locale,
                        NotificationTemplateRecord.version.desc(),
                    )
                ).scalars()
            )
            return tuple(_template_view(value, replayed=False) for value in values)

    def create_template(
        self,
        actor: NotificationActor,
        *,
        tenant_id: UUID | None,
        template_key: str,
        channel: NotificationChannel,
        locale: str,
        version: int,
        content_artifact_handle: str,
        content_sha256: str,
        variables_schema_sha256: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> NotificationTemplateView:
        created_at = _aware(now or datetime.now(timezone.utc))
        _require_platform_permission(actor, PLATFORM_NOTIFICATION_TEMPLATE_MANAGE_PERMISSION)
        key = _bounded(template_key, "template_key", 128)
        normalized_locale = normalize_locale(locale)
        if channel not in {"in_app", "email"} or type(version) is not int or version < 1:
            raise NotificationDeliveryError("notification_template_identity_invalid")
        artifact_handle = _template_artifact_handle(content_artifact_handle)
        content_hash = _sha256_value(content_sha256, "content")
        variables_hash = _sha256_value(variables_schema_sha256, "variables_schema")
        idempotency = _bounded(idempotency_key, "idempotency_key", 128)
        identity_values = (
            str(actor.actor_id),
            str(tenant_id or "platform"),
            key,
            channel,
            normalized_locale,
            idempotency,
        )
        request_values = (
            str(tenant_id or "platform"),
            key,
            channel,
            normalized_locale,
            str(version),
            artifact_handle,
            content_hash,
            variables_hash,
        )
        candidates = tuple(
            (
                candidate,
                candidate.digest_values(
                    domain="notification-template-create-idempotency",
                    values=identity_values,
                ),
                candidate.digest_values(
                    domain="notification-template-create-request",
                    values=request_values,
                ),
            )
            for candidate in self._digesters
        )
        with self._sessions.begin() as db:
            _apply_notification_delivery_rls(
                db,
                realm="staff",
                tenant_id=tenant_id,
                actor=actor,
                mutation="template_create",
            )
            for candidate, key_hmac, request_hmac in candidates:
                candidate_id = UUID(hex=key_hmac[:32])
                _apply_notification_delivery_rls(
                    db,
                    realm="staff",
                    tenant_id=tenant_id,
                    actor=actor,
                    template_id=candidate_id,
                    mutation="template_create",
                )
                existing = db.get(NotificationTemplateRecord, candidate_id)
                if existing is None:
                    continue
                if existing.hmac_key_id != candidate.key_id or not hmac.compare_digest(
                    existing.create_request_hmac, request_hmac
                ):
                    raise NotificationDeliveryError("notification_template_idempotency_conflict")
                return _template_view(existing, replayed=True)
            existing_version = db.execute(
                sa.select(NotificationTemplateRecord.id).where(
                    NotificationTemplateRecord.realm == "staff",
                    NotificationTemplateRecord.tenant_id.is_(tenant_id)
                    if tenant_id is None
                    else NotificationTemplateRecord.tenant_id == tenant_id,
                    NotificationTemplateRecord.template_key == key,
                    NotificationTemplateRecord.channel == channel,
                    NotificationTemplateRecord.locale == normalized_locale,
                    NotificationTemplateRecord.version == version,
                )
            ).scalar_one_or_none()
            if existing_version is not None:
                raise NotificationDeliveryError("notification_template_version_conflict")
            current_digester, key_hmac, request_hmac = candidates[0]
            template_id = UUID(hex=key_hmac[:32])
            _apply_notification_delivery_rls(
                db,
                realm="staff",
                tenant_id=tenant_id,
                actor=actor,
                template_id=template_id,
                mutation="template_create",
            )
            record = NotificationTemplateRecord(
                id=template_id,
                realm="staff",
                tenant_id=tenant_id,
                created_by_principal_id=actor.actor_id,
                template_key=key,
                channel=channel,
                locale=normalized_locale,
                version=version,
                content_artifact_handle=artifact_handle,
                content_sha256=content_hash,
                variables_schema_sha256=variables_hash,
                hmac_key_id=current_digester.key_id,
                create_idempotency_hmac=key_hmac,
                create_request_hmac=request_hmac,
                retire_idempotency_hmac=None,
                retire_request_hmac=None,
                status="active",
                created_at=created_at,
                retired_at=None,
            )
            db.add(record)
            db.flush()
            return _template_view(record, replayed=False)

    def retire_template(
        self,
        actor: NotificationActor,
        *,
        template_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> NotificationTemplateView:
        retired_at = _aware(now or datetime.now(timezone.utc))
        _require_platform_permission(actor, PLATFORM_NOTIFICATION_TEMPLATE_MANAGE_PERMISSION)
        key = _bounded(idempotency_key, "idempotency_key", 128)
        with self._sessions.begin() as db:
            _apply_notification_delivery_rls(
                db,
                realm="staff",
                tenant_id=None,
                actor=actor,
                template_id=template_id,
                mutation="template_read",
            )
            candidate = db.execute(
                sa.select(NotificationTemplateRecord).where(
                    NotificationTemplateRecord.id == template_id
                )
            ).scalar_one_or_none()
            if candidate is None:
                raise NotificationDeliveryError("notification_template_not_found")
            _apply_notification_delivery_rls(
                db,
                realm="staff",
                tenant_id=candidate.tenant_id,
                actor=actor,
                template_id=template_id,
                mutation="template_retire",
            )
            record = db.execute(
                sa.select(NotificationTemplateRecord)
                .where(NotificationTemplateRecord.id == template_id)
                .with_for_update()
            ).scalar_one_or_none()
            if record is None:
                raise NotificationDeliveryError("notification_template_not_found")
            digester = self._digester_for_key(record.hmac_key_id)
            key_hmac = digester.digest_values(
                domain="notification-template-retire-idempotency",
                values=(str(template_id), key),
            )
            request_hmac = digester.digest_values(
                domain="notification-template-retire-request",
                values=(str(template_id), str(expected_version)),
            )
            if record.retire_idempotency_hmac is not None:
                if not hmac.compare_digest(record.retire_idempotency_hmac, key_hmac):
                    raise NotificationDeliveryError(
                        "notification_template_retire_idempotency_conflict"
                    )
                if not hmac.compare_digest(record.retire_request_hmac or "", request_hmac):
                    raise NotificationDeliveryError(
                        "notification_template_retire_payload_conflict"
                    )
                return _template_view(record, replayed=True)
            if record.status != "active" or record.version != expected_version:
                raise NotificationDeliveryError("notification_template_retire_conflict")
            record.status = "retired"
            record.retire_idempotency_hmac = key_hmac
            record.retire_request_hmac = request_hmac
            record.retired_at = retired_at
            db.flush()
            return _template_view(record, replayed=False)

    def claim(
        self,
        identity: NotificationWorkloadIdentity,
        *,
        now: datetime,
    ) -> ClaimedNotificationDelivery | None:
        claimed_at = _aware(now)
        _validate_workload_identity(identity, claimed_at)
        for _ in range(8):
            with self._sessions.begin() as db:
                _apply_notification_dispatch_scan_rls(db)
                query = (
                    sa.select(NotificationDeliveryRecord)
                    .where(
                        sa.or_(
                            sa.and_(
                                NotificationDeliveryRecord.status.in_(("pending", "retry")),
                                NotificationDeliveryRecord.available_at <= claimed_at,
                            ),
                            sa.and_(
                                NotificationDeliveryRecord.status == "leased",
                                NotificationDeliveryRecord.lease_expires_at <= claimed_at,
                            ),
                        )
                    )
                    .order_by(
                        NotificationDeliveryRecord.available_at,
                        NotificationDeliveryRecord.id,
                    )
                    .limit(1)
                )
                if db.bind is not None and db.bind.dialect.name == "postgresql":
                    query = query.with_for_update(skip_locked=True)
                record = db.execute(query).scalar_one_or_none()
                if record is None:
                    return None
                recipient_id = record.recipient_user_id or record.recipient_principal_id
                if recipient_id is None:
                    raise NotificationDeliveryError("notification_recipient_invalid")
                dispatcher_actor = NotificationActor(
                    realm=record.realm,  # type: ignore[arg-type]
                    actor_id=recipient_id,
                    tenant_id=record.tenant_id,
                )
                _apply_notification_delivery_rls(
                    db,
                    realm=record.realm,
                    tenant_id=record.tenant_id,
                    actor=dispatcher_actor,
                    delivery_id=record.id,
                    template_id=record.template_id,
                    work_item_id=record.approval_work_item_id,
                    batch_id=record.operation_batch_id,
                    source_delivery_id=record.source_delivery_id,
                    event_type=record.event_type,
                    channels=(record.channel,),  # type: ignore[arg-type]
                    mutation="dispatch",
                )
                if self._approval_terminal(db, record):
                    self._suppress(record, "approval_terminal", claimed_at)
                    continue
                template = db.get(NotificationTemplateRecord, record.template_id)
                if template is None or template.status != "active":
                    self._suppress(record, "template_unavailable", claimed_at)
                    continue
                digester = self._digester_for_key(record.hmac_key_id)
                lease_token = secrets.token_urlsafe(32)
                record.status = "leased"
                record.attempt_count += 1
                record.leased_at = claimed_at
                record.lease_expires_at = claimed_at + timedelta(seconds=30)
                record.lease_token_hash = digester.digest_values(
                    domain="notification-delivery-lease",
                    values=(str(record.id), lease_token),
                )
                record.executor_identity_sha256 = sha256(identity.subject.encode()).hexdigest()
                record.lease_generation += 1
                record.version += 1
                record.updated_at = claimed_at
                db.flush()
                if record.lease_expires_at is None:
                    raise NotificationDeliveryError("notification_delivery_lease_invalid")
                return ClaimedNotificationDelivery(
                    delivery_id=record.id,
                    message_id=record.id,
                    tenant_id=record.tenant_id,
                    realm=record.realm,
                    recipient_id=recipient_id,
                    channel=record.channel,  # type: ignore[arg-type]
                    template_id=record.template_id,
                    approval_work_item_id=record.approval_work_item_id,
                    operation_batch_id=record.operation_batch_id,
                    source_delivery_id=record.source_delivery_id,
                    hmac_key_id=record.hmac_key_id,
                    recipient_ref=_recipient_ref(record),
                    template_key=template.template_key,
                    locale=template.locale,
                    template_version=template.version,
                    template_artifact_handle=template.content_artifact_handle,
                    template_content_sha256=template.content_sha256,
                    template_variables_schema_sha256=template.variables_schema_sha256,
                    event_type=record.event_type,
                    render_context_hmac=record.render_context_hmac,
                    attempt_number=record.attempt_count,
                    lease_generation=record.lease_generation,
                    lease_token=lease_token,
                    lease_expires_at=_stored_time(record.lease_expires_at),
                )
        return None

    def ensure_sendable(
        self,
        claim: ClaimedNotificationDelivery,
        *,
        now: datetime,
    ) -> DeliverySettlement | None:
        checked_at = _aware(now)
        with self._sessions.begin() as db:
            record = self._locked_claim(db, claim, checked_at)
            if not self._approval_terminal(db, record):
                return None
            digester = self._digester_for_key(record.hmac_key_id)
            fingerprint = digester.digest_values(
                domain="notification-suppression", values=("approval_terminal",)
            )
            self._attempt(
                db,
                record,
                outcome="suppressed",
                completed_at=checked_at,
                error_code="approval_terminal",
                error_hmac=fingerprint,
            )
            self._suppress(record, "approval_terminal", checked_at)
            return DeliverySettlement(
                delivery_id=record.id,
                status="suppressed",
                attempt_number=record.attempt_count,
            )

    def complete(
        self,
        claim: ClaimedNotificationDelivery,
        *,
        receipt: DeliveryProviderReceipt,
        now: datetime,
    ) -> DeliverySettlement:
        completed_at = _aware(now)
        _validate_provider_receipt(receipt)
        with self._sessions.begin() as db:
            record = self._locked_claim(db, claim, completed_at)
            inflight = (
                "approval_terminal_after_send" if self._approval_terminal(db, record) else None
            )
            self._attempt(
                db,
                record,
                outcome="succeeded",
                completed_at=completed_at,
                provider_request_hmac=receipt.provider_request_hmac,
                provider_receipt_hmac=receipt.provider_receipt_hmac,
                inflight_boundary_code=inflight,
            )
            record.status = "succeeded"
            record.provider_message_hmac = receipt.provider_message_hmac
            record.delivered_at = completed_at
            record.inflight_boundary_code = inflight
            self._clear_lease(record)
            record.last_error_code = None
            record.last_error_hmac = None
            record.version += 1
            record.updated_at = completed_at
            db.flush()
            return DeliverySettlement(
                delivery_id=record.id,
                status="succeeded",
                attempt_number=record.attempt_count,
            )

    def fail(
        self,
        claim: ClaimedNotificationDelivery,
        *,
        error_code: str,
        provider_status: int | None,
        retryable: bool,
        now: datetime,
    ) -> DeliverySettlement:
        failed_at = _aware(now)
        normalized_error, normalized_retryable = _validate_delivery_failure(
            error_code=error_code,
            provider_status=provider_status,
            retryable=retryable,
        )
        with self._sessions.begin() as db:
            record = self._locked_claim(db, claim, failed_at)
            digester = self._digester_for_key(record.hmac_key_id)
            error_fingerprint = digester.digest(
                domain="notification-provider-error",
                error_code=normalized_error,
                provider_status=provider_status,
            )
            retry = normalized_retryable and record.attempt_count < record.max_attempts
            next_available = (
                failed_at + timedelta(seconds=min(900, 2 ** min(record.attempt_count, 9)))
                if retry
                else None
            )
            outcome: Literal["retry", "dead_letter"] = "retry" if retry else "dead_letter"
            self._attempt(
                db,
                record,
                outcome=outcome,
                completed_at=failed_at,
                error_code=normalized_error,
                error_hmac=error_fingerprint,
                next_available_at=next_available,
            )
            record.status = outcome
            record.available_at = next_available or failed_at
            record.last_error_code = normalized_error
            record.last_error_hmac = error_fingerprint
            self._clear_lease(record)
            record.version += 1
            record.updated_at = failed_at
            if (
                outcome == "dead_letter"
                and record.event_type != "notification.delivery_dead_letter"
                and self._dead_letter_sink is not None
            ):
                self._dead_letter_sink.enqueue_dead_letter_in_transaction(
                    self,
                    db,
                    tenant_id=record.tenant_id,
                    delivery_id=record.id,
                    replay_generation=record.replay_generation,
                    now=failed_at,
                )
            db.flush()
            return DeliverySettlement(
                delivery_id=record.id,
                status=outcome,
                attempt_number=record.attempt_count,
                available_at=next_available,
            )

    def _locked_claim(
        self,
        db: Session,
        claim: ClaimedNotificationDelivery,
        at: datetime,
    ) -> NotificationDeliveryRecord:
        _notification_scope(claim.realm, claim.tenant_id)
        expected_ref = (
            f"user:{claim.recipient_id}"
            if claim.realm == "tenant"
            else f"principal:{claim.recipient_id}"
        )
        if claim.recipient_ref != expected_ref:
            raise NotificationDeliveryError("notification_delivery_claim_invalid")
        _apply_notification_delivery_rls(
            db,
            realm=claim.realm,
            tenant_id=claim.tenant_id,
            actor=NotificationActor(
                realm=claim.realm,  # type: ignore[arg-type]
                actor_id=claim.recipient_id,
                tenant_id=claim.tenant_id,
            ),
            delivery_id=claim.delivery_id,
            template_id=claim.template_id,
            work_item_id=claim.approval_work_item_id,
            batch_id=claim.operation_batch_id,
            source_delivery_id=claim.source_delivery_id,
            mutation="dispatch",
        )
        record = db.execute(
            sa.select(NotificationDeliveryRecord)
            .where(NotificationDeliveryRecord.id == claim.delivery_id)
            .with_for_update()
        ).scalar_one_or_none()
        if record is None:
            raise NotificationDeliveryError("notification_delivery_not_found")
        recipient_id = record.recipient_user_id or record.recipient_principal_id
        if (
            recipient_id is None
            or record.realm != claim.realm
            or record.tenant_id != claim.tenant_id
            or recipient_id != claim.recipient_id
            or record.template_id != claim.template_id
            or record.approval_work_item_id != claim.approval_work_item_id
            or record.operation_batch_id != claim.operation_batch_id
            or record.source_delivery_id != claim.source_delivery_id
            or record.channel != claim.channel
            or record.event_type != claim.event_type
            or record.hmac_key_id != claim.hmac_key_id
        ):
            raise NotificationDeliveryError("notification_delivery_claim_invalid")
        digester = self._digester_for_key(record.hmac_key_id)
        token_hmac = digester.digest_values(
            domain="notification-delivery-lease",
            values=(str(record.id), claim.lease_token),
        )
        if (
            record.status != "leased"
            or record.lease_generation != claim.lease_generation
            or record.attempt_count != claim.attempt_number
            or record.lease_expires_at is None
            or _stored_time(record.lease_expires_at) <= at
            or not hmac.compare_digest(record.lease_token_hash or "", token_hmac)
        ):
            raise NotificationDeliveryError("notification_delivery_lease_lost")
        return record

    def _attempt(
        self,
        db: Session,
        record: NotificationDeliveryRecord,
        *,
        outcome: str,
        completed_at: datetime,
        provider_request_hmac: str | None = None,
        provider_receipt_hmac: str | None = None,
        error_code: str | None = None,
        error_hmac: str | None = None,
        inflight_boundary_code: str | None = None,
        next_available_at: datetime | None = None,
    ) -> None:
        if record.leased_at is None or record.executor_identity_sha256 is None:
            raise NotificationDeliveryError("notification_delivery_lease_invalid")
        db.add(
            NotificationDeliveryAttemptRecord(
                id=uuid4(),
                delivery_id=record.id,
                realm=record.realm,
                tenant_id=record.tenant_id,
                recipient_user_id=record.recipient_user_id,
                recipient_principal_id=record.recipient_principal_id,
                attempt_number=record.attempt_count,
                lease_generation=record.lease_generation,
                outcome=outcome,
                content_hmac=record.render_context_hmac,
                provider_request_hmac=provider_request_hmac,
                provider_receipt_hmac=provider_receipt_hmac,
                error_code=error_code,
                error_hmac=error_hmac,
                inflight_boundary_code=inflight_boundary_code,
                hmac_key_id=record.hmac_key_id,
                executor_identity_sha256=record.executor_identity_sha256,
                started_at=record.leased_at,
                completed_at=completed_at,
                next_available_at=next_available_at,
                created_at=completed_at,
            )
        )

    @staticmethod
    def _approval_terminal(db: Session, record: NotificationDeliveryRecord) -> bool:
        if record.approval_work_item_id is None or record.event_type not in {
            "approval.requested",
            "approval.reminder",
            "approval.escalated",
        }:
            return False
        status = db.execute(
            sa.select(ApprovalWorkItemRecord.status).where(
                ApprovalWorkItemRecord.id == record.approval_work_item_id
            )
        ).scalar_one_or_none()
        return status is None or status != "pending"

    @staticmethod
    def _suppress(record: NotificationDeliveryRecord, code: str, at: datetime) -> None:
        record.status = "suppressed"
        record.suppression_code = code
        record.provider_message_hmac = None
        record.delivered_at = None
        record.last_error_code = None
        record.last_error_hmac = None
        NotificationDeliveryService._clear_lease(record)
        record.version += 1
        record.updated_at = at

    @staticmethod
    def _clear_lease(record: NotificationDeliveryRecord) -> None:
        record.leased_at = None
        record.lease_expires_at = None
        record.lease_token_hash = None
        record.executor_identity_sha256 = None

    @staticmethod
    def _preference(
        db: Session,
        *,
        realm: str,
        tenant_id: UUID | None,
        recipient_id: UUID,
        event_type: str,
        channel: str,
    ) -> NotificationPreferenceRecord | None:
        recipient = (
            NotificationPreferenceRecord.recipient_user_id == recipient_id
            if realm == "tenant"
            else NotificationPreferenceRecord.recipient_principal_id == recipient_id
        )
        values = tuple(
            db.execute(
                sa.select(NotificationPreferenceRecord).where(
                    NotificationPreferenceRecord.realm == realm,
                    (
                        _tenant_or_global(NotificationPreferenceRecord.tenant_id, tenant_id)
                        if realm == "staff"
                        else NotificationPreferenceRecord.tenant_id == tenant_id
                    ),
                    recipient,
                    NotificationPreferenceRecord.event_type == event_type,
                    NotificationPreferenceRecord.channel == channel,
                )
            ).scalars()
        )
        return next((value for value in values if value.tenant_id == tenant_id), None) or (
            values[0] if values else None
        )

    @staticmethod
    def _active_template_ids(
        db: Session,
        *,
        tenant_id: UUID | None,
        event_type: str,
        locale: str,
        channels: tuple[NotificationChannel, ...],
    ) -> dict[NotificationChannel, UUID]:
        values = tuple(
            db.execute(
                sa.select(NotificationTemplateRecord).where(
                    NotificationTemplateRecord.realm == "staff",
                    _tenant_or_global(NotificationTemplateRecord.tenant_id, tenant_id),
                    NotificationTemplateRecord.template_key == event_type,
                    NotificationTemplateRecord.channel.in_(channels),
                    NotificationTemplateRecord.locale.in_((locale, "en-US")),
                    NotificationTemplateRecord.status == "active",
                )
            ).scalars()
        )
        selected: dict[NotificationChannel, UUID] = {}
        for channel in channels:
            matches = tuple(value for value in values if value.channel == channel)
            match = min(
                matches,
                key=lambda value: (
                    0 if value.tenant_id == tenant_id and tenant_id is not None else 1,
                    0 if value.locale == locale else 1,
                    -value.version,
                ),
                default=None,
            )
            if match is None:
                raise NotificationDeliveryError("notification_template_not_found")
            selected[channel] = match.id
        return selected

    @staticmethod
    def _template(
        db: Session,
        *,
        template_id: UUID,
        tenant_id: UUID | None,
        template_key: str,
        channel: str,
        locale: str,
    ) -> NotificationTemplateRecord:
        values = tuple(
            db.execute(
                sa.select(NotificationTemplateRecord)
                .where(
                    NotificationTemplateRecord.id == template_id,
                    NotificationTemplateRecord.realm == "staff",
                    _tenant_or_global(NotificationTemplateRecord.tenant_id, tenant_id),
                    NotificationTemplateRecord.template_key == template_key,
                    NotificationTemplateRecord.channel == channel,
                    NotificationTemplateRecord.locale.in_((locale, "en-US")),
                    NotificationTemplateRecord.status == "active",
                )
                .order_by(NotificationTemplateRecord.version.desc())
            ).scalars()
        )
        for tenant_match in (tenant_id, None):
            for locale_match in (locale, "en-US"):
                match = next(
                    (
                        value
                        for value in values
                        if value.tenant_id == tenant_match and value.locale == locale_match
                    ),
                    None,
                )
                if match is not None:
                    return match
            if tenant_id is None:
                break
        raise NotificationDeliveryError("notification_template_not_found")

    def _digester_for_key(self, key_id: str) -> NotificationErrorDigester:
        for value in self._digesters:
            if hmac.compare_digest(value.key_id, key_id):
                return value
        raise NotificationDeliveryError("notification_hmac_key_unavailable")


def _validate_workload_identity(identity: NotificationWorkloadIdentity, at: datetime) -> None:
    authenticated_at = _aware(identity.authenticated_at)
    expires_at = _aware(identity.expires_at)
    if (
        identity.audience != "omnigent:notification-delivery"
        or not identity.subject.strip()
        or len(identity.subject) > 1024
        or "\x00" in identity.subject
        or authenticated_at > at
        or at - authenticated_at > _WORKLOAD_IDENTITY_MAX_AGE
        or expires_at <= at
        or expires_at - authenticated_at > _WORKLOAD_IDENTITY_MAX_TTL
    ):
        raise NotificationDeliveryError("notification_workload_identity_invalid")


def _validate_provider_receipt(receipt: DeliveryProviderReceipt) -> None:
    if (
        not receipt.provider.strip()
        or len(receipt.provider) > 64
        or "\x00" in receipt.provider
        or not all(
            _is_sha256_hmac(value)
            for value in (
                receipt.provider_request_hmac,
                receipt.provider_receipt_hmac,
                receipt.provider_message_hmac,
            )
        )
    ):
        raise NotificationDeliveryError("notification_provider_receipt_invalid")


def _validate_delivery_failure(
    *, error_code: str, provider_status: int | None, retryable: bool
) -> tuple[str, bool]:
    code = _bounded(error_code, "provider_error_code", 128)
    if code not in _FAILURE_CODES or type(retryable) is not bool:
        raise NotificationDeliveryError("notification_delivery_failure_invalid")
    if provider_status is not None:
        if type(provider_status) is not int or not 100 <= provider_status <= 599:
            raise NotificationDeliveryError("notification_delivery_failure_invalid")
        expected_code, expected_retryable = classify_provider_status(provider_status)
        if code != expected_code or retryable is not expected_retryable:
            raise NotificationDeliveryError("notification_delivery_failure_invalid")
        return code, expected_retryable
    if retryable and code != "notification_provider_unavailable":
        raise NotificationDeliveryError("notification_delivery_failure_invalid")
    return code, retryable


def _is_sha256_hmac(value: str) -> bool:
    return len(value) == 64 and all(character in _HEX_DIGITS for character in value)


def _delivery_view(value: NotificationDeliveryRecord) -> NotificationDeliveryView:
    return NotificationDeliveryView(
        id=value.id,
        realm=value.realm,
        tenant_id=value.tenant_id,
        event_type=value.event_type,
        channel=value.channel,
        approval_work_item_id=value.approval_work_item_id,
        operation_batch_id=value.operation_batch_id,
        source_delivery_id=value.source_delivery_id,
        status=value.status,
        attempt_count=value.attempt_count,
        max_attempts=value.max_attempts,
        replay_generation=value.replay_generation,
        available_at=_stored_time(value.available_at),
        delivered_at=_stored_time(value.delivered_at) if value.delivered_at else None,
        recipient_read_at=(
            _stored_time(value.recipient_read_at) if value.recipient_read_at else None
        ),
        suppression_code=value.suppression_code,
        inflight_boundary_code=value.inflight_boundary_code,
        last_error_code=value.last_error_code,
        version=value.version,
    )


def _preference_view(
    value: NotificationPreferenceRecord, *, replayed: bool
) -> NotificationPreferenceView:
    return NotificationPreferenceView(
        id=value.id,
        event_type=value.event_type,
        channel=value.channel,
        enabled=value.enabled,
        locale=value.locale,
        version=value.version,
        replayed=replayed,
    )


def _template_view(
    value: NotificationTemplateRecord, *, replayed: bool
) -> NotificationTemplateView:
    return NotificationTemplateView(
        id=value.id,
        realm=value.realm,
        tenant_id=value.tenant_id,
        template_key=value.template_key,
        channel=value.channel,
        locale=value.locale,
        version=value.version,
        content_artifact_handle=value.content_artifact_handle,
        content_sha256=value.content_sha256,
        variables_schema_sha256=value.variables_schema_sha256,
        status=value.status,
        replayed=replayed,
    )


def _delivery_visible(value: NotificationDeliveryRecord, actor: NotificationActor) -> bool:
    recipient = value.recipient_user_id or value.recipient_principal_id
    return (
        value.realm == actor.realm
        and (
            (actor.realm == "staff" and actor.tenant_id is None)
            or value.tenant_id == actor.tenant_id
        )
        and recipient == actor.actor_id
    )


def _preference_visible(value: NotificationPreferenceRecord, actor: NotificationActor) -> bool:
    recipient = value.recipient_user_id or value.recipient_principal_id
    return (
        value.realm == actor.realm
        and (
            (actor.realm == "staff" and actor.tenant_id is None)
            or value.tenant_id == actor.tenant_id
        )
        and recipient == actor.actor_id
    )


def _recipient_ref(value: NotificationDeliveryRecord) -> str:
    if value.recipient_user_id is not None:
        return f"user:{value.recipient_user_id}"
    if value.recipient_principal_id is not None:
        return f"principal:{value.recipient_principal_id}"
    raise NotificationDeliveryError("notification_recipient_invalid")


def _notification_scope(realm: str, tenant_id: UUID | None) -> None:
    if realm not in {"tenant", "staff"} or (realm == "tenant" and tenant_id is None):
        raise NotificationDeliveryError("notification_scope_invalid")


def _require_platform_permission(actor: NotificationActor, permission: str) -> None:
    if actor.realm != "staff" or permission not in getattr(actor, "permissions", frozenset()):
        raise NotificationDeliveryError("notification_platform_permission_forbidden")


def _template_artifact_handle(value: str) -> str:
    handle = _bounded(value, "template_artifact_handle", 128)
    if (
        len(handle) < 16
        or "://" in handle
        or handle.startswith("/")
        or "/" in handle
        or any(character.isspace() for character in handle)
    ):
        raise NotificationDeliveryError("notification_template_artifact_handle_invalid")
    return handle


def _sha256_value(value: str, field_name: str) -> str:
    normalized = value.strip().lower()
    if not _is_sha256_hmac(normalized):
        raise NotificationDeliveryError(f"notification_template_{field_name}_sha256_invalid")
    return normalized


def _tenant_or_global(
    column: InstrumentedAttribute[UUID | None], tenant_id: UUID | None
) -> sa.ColumnElement[bool]:
    if tenant_id is None:
        return column.is_(None)
    return sa.or_(column == tenant_id, column.is_(None))


def _event_type(value: str) -> str:
    cleaned = _bounded(value, "event_type", 128)
    if cleaned not in NOTIFICATION_EVENT_TYPES:
        raise NotificationDeliveryError("notification_event_type_invalid")
    return cleaned


def _bounded(value: str, field_name: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or "\x00" in cleaned:
        raise NotificationDeliveryError(f"notification_{field_name}_invalid")
    return cleaned


def _stored_time(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else _aware(value)


def _apply_notification_delivery_rls(
    db: Session,
    *,
    realm: str,
    tenant_id: UUID | None,
    actor: NotificationActor,
    delivery_id: UUID | None = None,
    template_id: UUID | None = None,
    work_item_id: UUID | None = None,
    batch_id: UUID | None = None,
    source_delivery_id: UUID | None = None,
    event_type: str = "",
    channels: tuple[NotificationChannel, ...] = (),
    locale: str = "",
    mutation: str = "read",
) -> None:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    _notification_scope(realm, tenant_id)
    db.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_realm', :realm, true), "
            "set_config('app.notification_actor_realm', :actor_realm, true), "
            "set_config('app.notification_tenant_id', :tenant_id, true), "
            "set_config('app.notification_recipient_user_id', :user_id, true), "
            "set_config('app.notification_staff_principal_id', :principal_id, true), "
            "set_config('app.notification_delivery_id', :delivery_id, true), "
            "set_config('app.notification_template_id', :template_id, true), "
            "set_config('app.notification_work_item_id', :work_item_id, true), "
            "set_config('app.notification_batch_id', :batch_id, true), "
            "set_config('app.notification_dead_letter_source_delivery_id', "
            ":source_delivery_id, true), "
            "set_config('app.notification_event_type', :event_type, true), "
            "set_config('app.notification_channels', :channels, true), "
            "set_config('app.notification_locale', :locale, true), "
            "set_config('app.notification_mutation', :mutation, true)"
        ),
        {
            "realm": realm,
            "actor_realm": actor.realm,
            "tenant_id": str(tenant_id) if tenant_id is not None else "",
            "user_id": str(actor.actor_id) if actor.realm == "tenant" else "",
            "principal_id": str(actor.actor_id) if actor.realm == "staff" else "",
            "delivery_id": str(delivery_id) if delivery_id else "",
            "template_id": str(template_id) if template_id else "",
            "work_item_id": str(work_item_id) if work_item_id else "",
            "batch_id": str(batch_id) if batch_id else "",
            "source_delivery_id": str(source_delivery_id) if source_delivery_id else "",
            "event_type": event_type,
            "channels": ",".join(channels),
            "locale": locale,
            "mutation": mutation,
        },
    )


def _apply_notification_dispatch_scan_rls(db: Session) -> None:
    """Clear human/exact-target claims for the dispatcher's bounded queue scan."""

    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    db.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_realm', '', true), "
            "set_config('app.notification_actor_realm', '', true), "
            "set_config('app.notification_tenant_id', '', true), "
            "set_config('app.notification_recipient_user_id', '', true), "
            "set_config('app.notification_staff_principal_id', '', true), "
            "set_config('app.notification_delivery_id', '', true), "
            "set_config('app.notification_template_id', '', true), "
            "set_config('app.notification_work_item_id', '', true), "
            "set_config('app.notification_batch_id', '', true), "
            "set_config('app.notification_dead_letter_source_delivery_id', '', true), "
            "set_config('app.notification_event_type', '', true), "
            "set_config('app.notification_channels', '', true), "
            "set_config('app.notification_locale', '', true), "
            "set_config('app.notification_mutation', 'dispatch_scan', true)"
        )
    )
